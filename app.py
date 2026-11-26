import hashlib
import hmac
import json
import logging
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
logger = logging.getLogger('spacematch.lp_webhook')
logger.setLevel(os.getenv('LOG_LEVEL', 'INFO').upper())


def log_webhook(level, event, **fields):
    """Emit one Render-friendly structured line without payloads or secret values."""
    getattr(logger, level)(
        'lp_webhook %s',
        json.dumps({'event': event, **fields}, separators=(',', ':'), sort_keys=True),
    )


def request_url_without_query(request):
    # Query strings are not expected here and may contain sensitive data.
    return str(request.url.replace(query=None, fragment=None))


def reject_auth(reason, **fields):
    log_webhook('warning', 'authentication_failed', reason=reason, **fields)
    raise HTTPException(401, 'Invalid webhook authentication')

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
    received_at = datetime.now(timezone.utc)
    incoming_url = request_url_without_query(request)
    body = await request.body()
    if len(body) > 1024 * 1024:
        log_webhook('warning', 'payload_rejected', reason='payload_too_large', body_length=len(body))
        raise HTTPException(413, 'Payload too large')
    timestamp = request.headers.get('x-lp-timestamp', '')
    signature = request.headers.get('x-lp-signature', '')
    version = request.headers.get('x-lp-signature-version', '')
    delivery = request.headers.get('x-lp-delivery-id', '')
    signature_is_hex = bool(re.fullmatch(r'[0-9a-fA-F]+', signature))
    header_names = sorted({name.lower() for name in request.headers.keys()})
    required_headers = ('x-lp-signature', 'x-lp-timestamp', 'x-lp-signature-version')
    missing_headers = [name for name in required_headers if not request.headers.get(name)]
    timestamp_has_valid_format = bool(re.fullmatch(r'[0-9]{1,16}', timestamp))
    timestamp_ms = int(timestamp) if timestamp_has_valid_format else None
    clock_difference_ms = round(time.time() * 1000 - timestamp_ms) if timestamp_ms is not None else None
    common_diagnostics = {
        'received_at': received_at.isoformat(),
        'header_names': header_names,
        'missing_signature_headers': missing_headers,
        'signature_present': bool(signature),
        'signature_length': len(signature),
        'signature_format': 'hex' if signature_is_hex else ('absent' if not signature else 'non_hex'),
        'signature_version': version or None,
        'webhook_timestamp': timestamp or None,
        'clock_difference_ms': clock_difference_ms,
        'delivery_id_present': bool(delivery),
        'delivery_id_length': len(delivery),
        'body_length': len(body),
        'configured_webhook_url': URL,
        'incoming_request_url': incoming_url,
        'webhook_url_matches_request': secrets.compare_digest(URL, incoming_url),
        'signing_secret_present': bool(SECRET),
        'signing_secret_length': len(SECRET),
    }
    log_webhook('info', 'request_received', **common_diagnostics)

    if missing_headers:
        reject_auth('missing_signature_headers', missing_headers=missing_headers)
    if version != 'v1':
        reject_auth('unsupported_signature_version', signature_version=version)
    if not timestamp_has_valid_format:
        reject_auth('invalid_timestamp_format', timestamp_length=len(timestamp))
    if abs(clock_difference_ms) > 300_000:
        reject_auth('expired_timestamp', clock_difference_ms=clock_difference_ms)
    if len(signature) != 64:
        reject_auth('invalid_signature_length', signature_length=len(signature))
    if not signature_is_hex:
        reject_auth('invalid_signature_encoding', signature_length=len(signature), signature_format='non_hex')

    expected = hmac.new(SECRET, timestamp.encode() + URL.encode() + body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature.lower()):
        # This does not relax verification. It only identifies a configured URL
        # mismatch when the exact incoming URL validates the same signed bytes.
        incoming_url_expected = hmac.new(
            SECRET, timestamp.encode() + incoming_url.encode() + body, hashlib.sha256
        ).hexdigest()
        incoming_url_signature_matches = hmac.compare_digest(incoming_url_expected, signature.lower())
        reason = 'configured_webhook_url_mismatch' if incoming_url_signature_matches else 'signature_mismatch'
        reject_auth(
            reason,
            webhook_url_matches_request=secrets.compare_digest(URL, incoming_url),
            incoming_url_signature_matches=incoming_url_signature_matches,
            possible_causes=(
                ['configured_webhook_url_mismatch']
                if incoming_url_signature_matches
                else ['signing_secret_mismatch', 'registered_url_mismatch', 'sender_signing_input_mismatch']
            ),
        )
    log_webhook('info', 'signature_verified', signature_version=version, body_length=len(body))

    if not re.fullmatch(r'[0-9a-f]{64}', delivery):
        log_webhook(
            'warning', 'delivery_rejected', reason='invalid_delivery_id',
            delivery_id_present=bool(delivery), delivery_id_length=len(delivery),
        )
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
        log_webhook('warning', 'payload_parsing_failed', reason='invalid_payload')
        raise HTTPException(400, 'Invalid payload')
    log_webhook('info', 'payload_parsed', event_name='leads', activity_type=activity)
    # Discard clearly unrelated hosts and anonymous non-capture activity.
    # Keep missing/relative source URLs for diagnosis.
    if host and host.lower() not in HOSTS:
        log_webhook('info', 'event_ignored', reason='other_host')
        return {'status': 'ignored', 'reason': 'other_host'}
    if activity not in CAPTURE and not (data.get('leadId') or data.get('leadEmail')):
        log_webhook('info', 'event_ignored', reason='anonymous_activity', activity_type=activity)
        return {'status': 'ignored', 'reason': 'anonymous_activity'}
    # Atomic insert + commit is all processing; acknowledge only after commit.
    try:
        with engine.begin() as conn:
            conn.execute(events.insert().values(delivery_id=delivery, received_at=datetime.now(timezone.utc).isoformat(), activity=activity, source_url=source, lead_id=str(data['leadId']) if data.get('leadId') else None, payload=body.decode('utf-8')))
    except IntegrityError:
        with engine.connect() as conn:
            existing = conn.execute(select(events.c.delivery_id).where(events.c.delivery_id == delivery)).first()
        if not existing:
            log_webhook('error', 'database_insert_failed', reason='integrity_error_not_duplicate')
            raise
        log_webhook('info', 'duplicate_event_detected', delivery_id_length=len(delivery))
        return {'status': 'duplicate'}
    except Exception:
        log_webhook('error', 'database_insert_failed', reason='unexpected_database_error')
        raise
    log_webhook('info', 'database_inserted', status='stored')
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
