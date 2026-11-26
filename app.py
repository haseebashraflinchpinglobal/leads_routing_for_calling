import hashlib
import hmac
import json
import os
import re
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from html import escape
from urllib.parse import urlsplit

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy import create_engine, MetaData, Table, Column, String, Text, select
from sqlalchemy.exc import IntegrityError

URL = os.environ['LP_WEBHOOK_URL']
SECRET = os.environ['LP_WEBHOOK_SECRET'].encode()
PASSWORD = os.environ['DASHBOARD_PASSWORD'].encode()
USERNAME = os.getenv('DASHBOARD_USERNAME', 'admin').encode()
DB = os.environ['DATABASE_URL']
if DB.startswith('postgres://'):
    DB = DB.replace('postgres://', 'postgresql+psycopg://', 1)
elif DB.startswith('postgresql://'):
    DB = DB.replace('postgresql://', 'postgresql+psycopg://', 1)
if len(SECRET) < 32 or len(PASSWORD) < 16:
    raise RuntimeError('Use a webhook secret of at least 32 characters and a dashboard password of at least 16 characters.')
engine = create_engine(DB, pool_pre_ping=True, connect_args={'check_same_thread': False} if DB.startswith('sqlite') else {})
metadata = MetaData()
events = Table('lp_events', metadata,
    Column('delivery_id', String(64), primary_key=True),
    Column('received_at', String(40), nullable=False),
    Column('activity', Text, nullable=False),
    Column('source_url', Text, nullable=False),
    Column('lead_id', Text),
    Column('payload', Text, nullable=False))
CAPTURE = {'SIGNUP', 'GOOGLE_SIGN_ON', 'CONTACT_INQUIRY', 'HOME_VALUE', 'PROPERTY_ACCESS', 'FORCED_LEAD_CAPTURE', 'NEWSLETTER_SIGNUP', 'EBOOK', 'REFERRAL'}
HOSTS = {'spacematchinc.com', 'www.spacematchinc.com'}

@asynccontextmanager
async def lifespan(app):
    metadata.create_all(engine)
    yield
    engine.dispose()

app = FastAPI(title='SpaceMatch Lead Gateway — Shadow MVP', lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
basic = HTTPBasic()

def auth(credentials: HTTPBasicCredentials = Depends(basic)):
    user_ok = secrets.compare_digest(credentials.username.encode(), USERNAME)
    pass_ok = secrets.compare_digest(credentials.password.encode(), PASSWORD)
    if not (user_ok and pass_ok):
        raise HTTPException(401, 'Unauthorized', headers={'WWW-Authenticate': 'Basic'})

@app.middleware('http')
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    return response

@app.get('/health')
def health():
    with engine.connect() as conn:
        conn.execute(select(1))
    return {'status': 'ok', 'mode': 'shadow'}

@app.post('/webhooks/lp')
async def receive(request: Request):
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 1024 * 1024:
            raise HTTPException(413, 'Payload too large')
    body = bytes(body)
    timestamp = request.headers.get('x-lp-timestamp', '')
    signature = request.headers.get('x-lp-signature', '')
    version = request.headers.get('x-lp-signature-version', '')
    delivery = request.headers.get('x-lp-delivery-id', '')
    if version != 'v1' or not re.fullmatch(r'[0-9a-fA-F]{64}', signature) or not re.fullmatch(r'\d{13}', timestamp):
        raise HTTPException(401, 'Invalid signature headers')
    if abs(time.time() * 1000 - int(timestamp)) > 300_000:
        raise HTTPException(401, 'Expired signature')
    expected = hmac.new(SECRET, timestamp.encode() + URL.encode() + body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature.lower()):
        raise HTTPException(401, 'Invalid signature')
    if not re.fullmatch(r'[0-9a-f]{64}', delivery):
        raise HTTPException(400, 'Invalid delivery ID')
    try:
        payload = json.loads(body)
        data = payload['data']
        activity = data['activityType']
        source = data['activitySourceUrl']
        if payload['eventName'] != 'leads' or not isinstance(activity, str) or not isinstance(source, str):
            raise ValueError()
        host = urlsplit(source).hostname
    except (ValueError, KeyError, TypeError, AttributeError):
        raise HTTPException(400, 'Invalid payload')
    # Discard clearly unrelated hosts and anonymous non-capture activity.
    # Keep missing/relative source URLs for diagnosis.
    if host and host.lower() not in HOSTS:
        return {'status': 'ignored', 'reason': 'other_host'}
    if activity not in CAPTURE and not (data.get('leadId') or data.get('leadEmail')):
        return {'status': 'ignored', 'reason': 'anonymous_activity'}
    # Atomic insert + commit is all processing; acknowledge only after commit.
    try:
        with engine.begin() as conn:
            conn.execute(events.insert().values(delivery_id=delivery, received_at=datetime.now(timezone.utc).isoformat(), activity=activity, source_url=source, lead_id=str(data['leadId']) if data.get('leadId') else None, payload=body.decode('utf-8')))
    except IntegrityError:
        with engine.connect() as conn:
            existing = conn.execute(select(events.c.delivery_id).where(events.c.delivery_id == delivery)).first()
        if not existing:
            raise
        return {'status': 'duplicate'}
    return {'status': 'stored'}

@app.get('/api/events', dependencies=[Depends(auth)])
def get_events():
    with engine.connect() as conn:
        rows = conn.execute(select(events).order_by(events.c.received_at.desc()).limit(100)).mappings().all()
    return [{'delivery_id': r['delivery_id'], 'received_at': r['received_at'], **{'payload': json.loads(r['payload'])}} for r in rows]

@app.get('/', response_class=HTMLResponse, dependencies=[Depends(auth)])
def dashboard():
    rows = get_events()
    def e(value): return escape(str(value if value is not None else ''))
    parts = []
    for row in rows:
        data = row['payload']['data']
        name = ' '.join(str(data.get(k) or '') for k in ('leadFirstName','leadLastName')).strip()
        parts.append(f"<tr><td>{e(row['received_at'])}</td><td>{e(data.get('activityType'))}</td><td>{e(name)}<br>{e(data.get('leadEmail'))}<br>{e(data.get('leadPhoneNumber'))}</td><td>{e(data.get('activitySourceUrl'))}</td><td><details><summary>Raw JSON</summary><pre>{e(json.dumps(row['payload'], indent=2, ensure_ascii=False))}</pre></details></td></tr>")
    return HTMLResponse('''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SpaceMatch Lead Gateway</title><style>body{font:15px system-ui;margin:32px auto;padding:0 18px;max-width:1200px;color:#172b3a;background:#f7f9fb}h1{margin-bottom:4px}p{color:#506477}a{color:#145ca3}table{width:100%;border-collapse:collapse;background:white}td,th{padding:12px;text-align:left;border-bottom:1px solid #dce3ea;vertical-align:top;overflow-wrap:anywhere}th{background:#eaf0f5}pre{white-space:pre-wrap;max-width:450px}summary{cursor:pointer;color:#145ca3}.table{overflow:auto}.tag{display:inline-block;background:#e4efe9;padding:6px 12px;border-radius:6px}</style></head><body><h1>SpaceMatch Lead Gateway</h1><span class="tag">Shadow mode — no CRM writes</span><p>Latest 100 stored events. Refresh after submitting a test form. Events are not necessarily distinct leads.</p><p><a href="/">Refresh</a> · <a href="/api/events">JSON feed</a></p><div class="table"><table><thead><tr><th>Received (UTC)</th><th>Activity</th><th>Contact</th><th>Source URL</th><th>Payload</th></tr></thead><tbody>''' + ''.join(parts) + ('' if parts else '<tr><td colspan="5">No events received yet.</td></tr>') + '</tbody></table></div></body></html>')
