# SpaceMatch Lead Gateway — shadow MVP

Receive signed LP lead activity, store relevant events and view them in a password-protected dashboard. No Lofty API calls, outbound notifications or CRM writes. No existing subscription is modified by the create command. LP retries can requeue an event for all subscribers, so monitor existing intake and remove this new subscription if it causes errors.

## Deploy on Render
1. Push these files to a private Git repository. Create a Render PostgreSQL database and a Python web service in the same region. Prefer an always-on instance; free instances sleep and free PostgreSQL expires after 30 days.
2. Build command: `pip install -r requirements.txt`
3. Start command: `uvicorn app:app --host 0.0.0.0 --port $PORT`
4. Health check path: `/health`.
5. Configure environment variables: `DATABASE_URL` (Render internal database URL), `LP_WEBHOOK_URL` (exact HTTPS URL ending `/webhooks/lp`, no trailing slash), `LP_WEBHOOK_SECRET` (random, at least 32 characters), `DASHBOARD_USERNAME` (admin), `DASHBOARD_PASSWORD` (random, at least 16 characters). Do not add LP API credentials to the web service. Generate secrets with `openssl rand -hex 32`.
6. Visit `/health` and `/` and verify that the dashboard requires authentication before registering the webhook.

## Register a separate webhook from your trusted local terminal
```bash
read -rsp 'LP API key: ' LP_API_KEY; echo; export LP_API_KEY
read -rsp 'Webhook signing secret (same as Render): ' LP_WEBHOOK_SECRET; echo; export LP_WEBHOOK_SECRET
export LP_WEBHOOK_URL='https://YOUR-SERVICE.onrender.com/webhooks/lp'
python manage_webhook.py list
python manage_webhook.py create
```
Save the new subscription ID securely. Do not repeat create if the result is ambiguous; list first. Never delete any pre-existing subscription. To clean up, run `python manage_webhook.py delete --id YOUR_MVP_ID` before stopping the service. Confirm the ID is the new MVP subscription. Then delete test data/database as appropriate. Do not share raw payloads or credentials publicly.

## Test
Use an owned email and consented phone, a unique test name, and coordinate with the team: existing automation can still contact your test identity. Submit contact, buyer-access, IDX signup/contact agent and valuation forms independently. Refresh the authenticated dashboard and compare LP and Lofty records. Repeated events from one lead are normal. Missing identity fields are allowed. Anonymous non-capture activity and clearly other-domain URLs are ignored; relative/empty URLs retained for diagnosis. This is an event inbox, not a canonical contact database. All stored fields are raw LP data, including potentially private data; limit access and delete the disposable database when done. No automated retention in this MVP.

## Local run
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt pytest httpx
cp .env.example .env
# edit .env with random values, then:
set -a; source .env; set +a
uvicorn app:app --reload
python -m pytest -q
```
Tests simulate LP signatures using local SQLite. Production PostgreSQL and live webhook deliveries are not tested by these tests. The receiver requires signed requests and a timestamp within five minutes. See https://docs.luxurypresence.com/reference/webhookcontroller_createwebhook for the signature and retry contract.

## Synthetic deployed-endpoint diagnostic
This sends a clearly labelled synthetic event, not a genuine LP event. It uses
the exact production signing inputs but does not prove that the LP subscription
has the same URL and secret. Run it only from a trusted terminal; do not put the
secret in shell history or source control.

```bash
read -rsp 'Webhook signing secret (same as Render): ' LP_WEBHOOK_SECRET; echo; export LP_WEBHOOK_SECRET
export LP_WEBHOOK_URL='https://leads-routing-for-calling.onrender.com/webhooks/lp'
python send_synthetic_webhook.py
```

The response should be `HTTP 200 {"status":"stored"}` and the dashboard row is
labelled `SYNTHETIC WEBHOOK DIAGNOSTIC`. Render logs contain authentication,
parsing and insertion status but never the secret, complete signature, delivery
ID, or payload. A successful synthetic request verifies the deployed receiver's
configured URL and secret; it does not verify LP's stored subscription values.
