import asyncio
import hashlib
import hmac
import json
import os
import tempfile
import time

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy import func, select
from starlette.requests import Request


folder = tempfile.TemporaryDirectory()
os.environ.update(
    DATABASE_URL='sqlite:///' + folder.name + '/test.db',
    LP_WEBHOOK_URL='https://example.test/webhooks/lp',
    LP_WEBHOOK_SECRET='s' * 40,
    DASHBOARD_PASSWORD='p' * 24,
)
from app import app, engine, events, metadata, receive


PAYLOAD = {
    'eventName': 'leads',
    'companyId': 'synthetic-test',
    'data': {
        'activityType': 'CONTACT_INQUIRY',
        'activitySourceUrl': 'https://spacematchinc.com/contact',
        'leadFirstName': 'Synthetic',
        'leadId': 'synthetic-test-lead',
    },
}


def signed_headers(
    body,
    delivery='a' * 64,
    *,
    secret=b's' * 40,
    url='https://example.test/webhooks/lp',
    timestamp=None,
):
    timestamp = timestamp or str(int(time.time() * 1000))
    signature = hmac.new(
        secret, timestamp.encode() + url.encode() + body, hashlib.sha256
    ).hexdigest()
    return {
        'x-lp-timestamp': timestamp,
        'x-lp-signature': signature,
        'x-lp-signature-version': 'v1',
        'x-lp-delivery-id': delivery,
        'content-type': 'application/json',
    }


def invoke_webhook(body, headers=None):
    request_headers = {
        key.lower().encode(): value.encode() for key, value in (headers or {}).items()
    }
    scope = {
        'type': 'http',
        'asgi': {'version': '3.0'},
        'http_version': '1.1',
        'method': 'POST',
        'scheme': 'https',
        'server': ('example.test', 443),
        'client': ('127.0.0.1', 12345),
        'path': '/webhooks/lp',
        'raw_path': b'/webhooks/lp',
        'query_string': b'',
        'headers': list(request_headers.items()),
    }

    async def receive_body():
        return {'type': 'http.request', 'body': body, 'more_body': False}

    return asyncio.run(receive(Request(scope, receive_body)))


@pytest.fixture(autouse=True)
def empty_database():
    metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(events.delete())


@pytest.fixture
def body():
    return json.dumps(PAYLOAD, separators=(',', ':')).encode()


def assert_auth_rejected(body, headers):
    with pytest.raises(HTTPException) as exc:
        invoke_webhook(body, headers)
    assert exc.value.status_code == 401
    assert exc.value.detail == 'Invalid webhook authentication'


def test_valid_signed_webhook_is_persisted(body):
    assert invoke_webhook(body, signed_headers(body)) == {'status': 'stored'}
    with engine.connect() as conn:
        row = conn.execute(select(events)).mappings().one()
    assert json.loads(row['payload'])['companyId'] == 'synthetic-test'


def test_asgi_route_accepts_valid_signed_webhook(body):
    async def post():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url='https://example.test'
        ) as client:
            return await client.post(
                '/webhooks/lp', content=body, headers=signed_headers(body, 'f' * 64)
            )

    response = asyncio.run(post())
    assert response.status_code == 200
    assert response.json() == {'status': 'stored'}


def test_missing_signature_headers_are_rejected(body):
    assert_auth_rejected(body, {'content-type': 'application/json'})


def test_invalid_signature_is_rejected(body):
    headers = signed_headers(body)
    headers['x-lp-signature'] = '0' * 64
    assert_auth_rejected(body, headers)


def test_invalid_signature_encoding_is_rejected(body):
    headers = signed_headers(body)
    headers['x-lp-signature'] = 'z' * 64
    assert_auth_rejected(body, headers)


def test_unsupported_signature_version_is_rejected(body):
    headers = signed_headers(body)
    headers['x-lp-signature-version'] = 'v2'
    assert_auth_rejected(body, headers)


def test_incorrect_timestamp_format_is_rejected(body):
    headers = signed_headers(body)
    headers['x-lp-timestamp'] = 'not-unix-milliseconds'
    assert_auth_rejected(body, headers)


def test_expired_timestamp_is_rejected(body):
    expired = str(int((time.time() - 301) * 1000))
    assert_auth_rejected(body, signed_headers(body, timestamp=expired))


def test_incorrect_signing_secret_is_rejected(body):
    assert_auth_rejected(body, signed_headers(body, secret=b'w' * 40))


def test_incorrect_webhook_url_is_rejected(body):
    assert_auth_rejected(
        body, signed_headers(body, url='https://wrong.example/webhooks/lp')
    )


def test_duplicate_delivery_is_acknowledged_once(body):
    headers = signed_headers(body)
    assert invoke_webhook(body, headers) == {'status': 'stored'}
    assert invoke_webhook(body, headers) == {'status': 'duplicate'}
    with engine.connect() as conn:
        count = conn.scalar(select(func.count()).select_from(events))
    assert count == 1
