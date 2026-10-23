"""Explicit first administrator setup. Password is never written to source."""
import getpass,json,os,pathlib,sys,re
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'backend'))
from store import Store
cfg=json.loads(pathlib.Path(os.environ.get('REDSEC_CONFIG','/etc/redsec-soc-console/config.json')).read_text())
name=input('First console administrator name: ').strip();password=getpass.getpass('Password (12+ characters): ')
if not re.fullmatch(r'[a-zA-Z0-9_.@-]{1,80}',name):raise SystemExit('Use a valid administrator name')
if len(password)<12 or password!=getpass.getpass('Confirm password: '):raise SystemExit('Password is too short or confirmation differs')
store=Store(cfg['database'])
if store.users():raise SystemExit('Console already has users; manage them through Users & audit')
store.initialize(name,password)
if os.name!='nt' and os.geteuid()==0:
 import pwd,grp
 uid=pwd.getpwnam('redsec-console').pw_uid;gid=grp.getgrnam('redsec-console').gr_gid
 for suffix in ('','-wal','-shm'):
  path=pathlib.Path(cfg['database']+suffix)
  if path.exists():os.chown(path,uid,gid);os.chmod(path,0o600)
print('Initial administrator created; no password file generated')
