"""Use LP API key only on your local machine, not on the receiver."""
import argparse
import json
import os
import urllib.request
import urllib.error

parser = argparse.ArgumentParser()
parser.add_argument('action', choices=['list', 'create', 'delete'])
parser.add_argument('--id', help='Only the MVP webhook ID, for deletion')
args = parser.parse_args()
base = 'https://api.luxurypresence.com/crm/v1/webhooks'
headers = {'x-api-key': os.environ['LP_API_KEY'], 'Content-Type': 'application/json', 'accept': 'application/json'}
method, body = 'GET', None
if args.action == 'create':
    method = 'POST'
    body = json.dumps({'name':'SpaceMatch Shadow MVP', 'url':os.environ['LP_WEBHOOK_URL'], 'secret':os.environ['LP_WEBHOOK_SECRET'], 'events':['leads']}).encode()
    if not os.environ['LP_WEBHOOK_URL'].startswith('https://'):
        parser.error('Use the deployed HTTPS receiver URL')
elif args.action == 'delete':
    import re
    if not args.id or not re.fullmatch(r'[A-Za-z0-9_-]+', args.id):
        parser.error('Provide the exact MVP subscription ID')
    if input(f'Delete ONLY subscription {args.id}? Type DELETE: ') != 'DELETE':
        raise SystemExit('Cancelled')
    base += '/' + args.id
    method = 'DELETE'
try:
    with urllib.request.urlopen(urllib.request.Request(base, data=body, headers=headers, method=method), timeout=30) as response:
        raw = response.read().decode()
        # Avoid printing secrets even if echoed by the API.
        for key in ('LP_API_KEY', 'LP_WEBHOOK_SECRET'):
            if os.environ.get(key): raw = raw.replace(os.environ[key], '[REDACTED]')
        print(response.status, raw)
except urllib.error.HTTPError as exc:
    print('LP API returned', exc.code, '(response body omitted to avoid exposing credentials)')
    raise SystemExit(1)
