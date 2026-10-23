"""Explicitly provision only the console's restricted indexer service account."""
import argparse,json,secrets,ssl,urllib.request,urllib.error,pathlib,os
parser=argparse.ArgumentParser()
parser.add_argument('--url',required=True);parser.add_argument('--ca',required=True);parser.add_argument('--admin-cert',required=True);parser.add_argument('--admin-key',required=True);parser.add_argument('--username',default='redsec_console_service');parser.add_argument('--output',required=True)
args=parser.parse_args()
if not args.url.startswith('https://'):raise SystemExit('TLS indexer URL required')
if not __import__('re').fullmatch(r'[a-zA-Z0-9_-]{1,80}',args.username):raise SystemExit('Invalid username')
out=pathlib.Path(args.output)
if out.exists():raise SystemExit('Output already exists; use the existing account configuration instead of rotating it implicitly')
ctx=ssl.create_default_context(cafile=args.ca);ctx.load_cert_chain(args.admin_cert,args.admin_key)
try:
 with urllib.request.urlopen(args.url.rstrip('/')+'/_plugins/_security/api/internalusers/'+args.username,context=ctx,timeout=20) as response:
  raise SystemExit('Account already exists; this helper will not rotate it implicitly')
except urllib.error.HTTPError as e:
 if e.code!=404:raise
password=secrets.token_urlsafe(36);role=args.username+'_read'
def put(path,body):
 request=urllib.request.Request(args.url.rstrip('/')+path,data=json.dumps(body).encode(),method='PUT',headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(request,context=ctx,timeout=20) as response:assert response.status in (200,201)
put('/_plugins/_security/api/roles/'+role,{'cluster_permissions':[],'index_permissions':[{'index_patterns':['wazuh-alerts-*','wazuh-archives-*'],'allowed_actions':['read']}],'tenant_permissions':[]})
put('/_plugins/_security/api/internalusers/'+args.username,{'password':password,'backend_roles':[]})
put('/_plugins/_security/api/rolesmapping/'+role,{'users':[args.username],'backend_roles':[],'hosts':[]})
fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as stream:json.dump({'indexer_user':args.username,'indexer_password':password},stream,indent=2)
print('Restricted account provisioned. Copy its fields from the protected output to the deployment config; do not commit that output.')
