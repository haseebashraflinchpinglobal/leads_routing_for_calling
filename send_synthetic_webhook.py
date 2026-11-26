"""Send a clearly labelled, correctly signed synthetic event to the receiver."""
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
import uuid


url = os.environ['LP_WEBHOOK_URL']
secret = os.environ['LP_WEBHOOK_SECRET'].encode()
if not url.startswith('https://'):
    raise SystemExit('LP_WEBHOOK_URL must be the deployed HTTPS /webhooks/lp URL')
if not url.endswith('/webhooks/lp'):
    raise SystemExit('LP_WEBHOOK_URL must end with /webhooks/lp (no trailing slash)')
if len(secret) < 32:
    raise SystemExit('LP_WEBHOOK_SECRET must contain the configured secret (at least 32 characters)')

diagnostic_id = uuid.uuid4().hex
payload = {
    'eventName': 'leads',
    'companyId': 'synthetic-diagnostic-not-luxury-presence',
    'data': {
        'activityType': 'CONTACT_INQUIRY',
        'activitySourceUrl': 'https://spacematchinc.com/__synthetic_webhook_diagnostic__',
        'leadId': f'synthetic-diagnostic-{diagnostic_id}',
        'leadFirstName': 'SYNTHETIC',
        'leadLastName': 'WEBHOOK DIAGNOSTIC',
    },
}
body = json.dumps(payload, separators=(',', ':')).encode()
timestamp = str(int(time.time() * 1000))
signature = hmac.new(secret, timestamp.encode() + url.encode() + body, hashlib.sha256).hexdigest()
delivery_id = hashlib.sha256(f'synthetic-diagnostic-{diagnostic_id}'.encode()).hexdigest()
headers = {
    'Content-Type': 'application/json',
    'x-lp-timestamp': timestamp,
    'x-lp-signature': signature,
    'x-lp-signature-version': 'v1',
    'x-lp-delivery-id': delivery_id,
}

print('Sending SYNTHETIC diagnostic event; this is not a genuine Luxury Presence delivery.')
try:
    with urllib.request.urlopen(
        urllib.request.Request(url, data=body, headers=headers, method='POST'), timeout=30
    ) as response:
        print('HTTP', response.status, response.read().decode())
except urllib.error.HTTPError as exc:
    print('HTTP', exc.code, exc.read().decode())
    raise SystemExit(1)
