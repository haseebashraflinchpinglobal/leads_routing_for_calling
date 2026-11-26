import os, tempfile, hashlib, hmac, json, time
from fastapi.testclient import TestClient
folder = tempfile.TemporaryDirectory()
os.environ.update(DATABASE_URL='sqlite:///'+folder.name+'/test.db', LP_WEBHOOK_URL='https://example.test/webhooks/lp', LP_WEBHOOK_SECRET='s'*40, DASHBOARD_PASSWORD='p'*24)
from app import app

def headers(body, delivery='a'*64):
    timestamp = str(int(time.time()*1000))
    signature = hmac.new(b's'*40, timestamp.encode()+b'https://example.test/webhooks/lp'+body, hashlib.sha256).hexdigest()
    return {'x-lp-timestamp':timestamp,'x-lp-signature':signature,'x-lp-signature-version':'v1','x-lp-delivery-id':delivery,'content-type':'application/json'}

def test_shadow_flow():
    with TestClient(app) as client:
        body=json.dumps({'eventName':'leads','companyId':'test','data':{'activityType':'CONTACT_INQUIRY','activitySourceUrl':'https://spacematchinc.com/contact','leadFirstName':'<script>','leadId':'test'}}).encode()
        assert client.get('/health').status_code==200
        assert client.post('/webhooks/lp',content=body).status_code==401
        assert client.post('/webhooks/lp',content=body,headers=headers(body)).json()['status']=='stored'
        assert client.post('/webhooks/lp',content=body,headers=headers(body)).json()['status']=='duplicate'
        assert client.get('/api/events').status_code==401
        assert len(client.get('/api/events',auth=('admin','p'*24)).json())==1
        page=client.get('/',auth=('admin','p'*24)).text
        assert '&lt;script&gt;' in page and '<script>' not in page
        other=json.dumps({'eventName':'leads','data':{'activityType':'VIEW_LISTING','activitySourceUrl':'https://spacematchinc.com/home-search/'}}).encode()
        assert client.post('/webhooks/lp',content=other,headers=headers(other,'b'*64)).json()['status']=='ignored'
        assert client.post('/webhooks/lp',content=other,headers=headers(body,'c'*64)).status_code==401
