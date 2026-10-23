"""Idempotent Ubuntu/systemd deployment. Existing config and database survive."""
import grp
import json
import os
import pathlib
import pwd
import re
import subprocess
import sys
from urllib.parse import urlparse

ROOT=pathlib.Path(__file__).resolve().parent.parent
if any(c.isspace() for c in str(ROOT)):raise SystemExit('Install the service under a path without whitespace, e.g. /opt/redsec-soc-console')
CONFIG_PATH=pathlib.Path(os.environ.get('REDSEC_CONFIG','/etc/redsec-soc-console/config.json'))
def run(*args):return subprocess.run(args,check=True)
def write_unit(name,source):
    pathlib.Path('/etc/systemd/system',name).write_text(source,encoding='utf-8')
def quoted(value):
    value=str(value)
    if any(c in value for c in ('\n','\r','%','"','\\')):raise ValueError('Unsupported character in systemd configuration path')
    return '"'+value+'"'

if os.geteuid()!=0:raise SystemExit('Run as root')
cfg=json.loads(CONFIG_PATH.read_text())
for key in ('indexer_url','indexer_ca','indexer_user','indexer_password','database','metadata','origins','tls_cert','tls_key','listen_host','listen_port'):
    if not cfg.get(key):raise SystemExit('Missing required configuration: '+key)
if cfg['indexer_password']=='REPLACE_WITH_GENERATED_SECRET':raise SystemExit('Replace the example indexer password before installation')
for value in (str(ROOT),str(CONFIG_PATH),cfg['database'],cfg['metadata']):
    if any(c.isspace() or c in '%"\\' for c in value):raise SystemExit('Use deployment paths without whitespace, percent signs, quotes or backslashes')
for key in ('database','metadata','tls_cert','tls_key','indexer_ca'):
    if not pathlib.Path(cfg[key]).is_absolute():raise SystemExit('Use an absolute '+key+' path')
if not 1<=int(cfg['listen_port'])<=65535:raise ValueError('Invalid listen port')
for origin in cfg['origins']:
    if urlparse(origin).scheme!='https' or not urlparse(origin).hostname:raise ValueError('Use explicit HTTPS origins')
for path in (cfg['tls_cert'],cfg['tls_key'],cfg['indexer_ca']):
    if not pathlib.Path(path).is_file():raise SystemExit('Required TLS/CA file missing: '+path)
if not (ROOT/'frontend/dist/index.html').exists():raise SystemExit('Build frontend first: cd frontend && npm ci && npm run build')
try:pwd.getpwnam('redsec-console')
except KeyError:run('useradd','--system','--home','/var/lib/redsec-soc-console','--shell','/usr/sbin/nologin','redsec-console')
account=pwd.getpwnam('redsec-console');gid=grp.getgrnam('redsec-console').gr_gid
data=pathlib.Path(cfg['database']).parent;data.mkdir(parents=True,exist_ok=True);os.chown(data,account.pw_uid,gid);os.chmod(data,0o700)
metadata=pathlib.Path(cfg['metadata']);metadata.mkdir(parents=True,exist_ok=True);os.chmod(metadata,0o755)
os.chown(CONFIG_PATH,0,gid);os.chmod(CONFIG_PATH,0o640)
for path in (cfg['tls_cert'],cfg['tls_key']):os.chown(path,0,gid);os.chmod(path,0o640)
venv=ROOT/'venv'
run(sys.executable,'-m','venv',str(venv))
run(str(venv/'bin/pip'),'install','--disable-pip-version-check','-r',str(ROOT/'backend/requirements.lock.txt'))
for folder in (ROOT/'backend',ROOT/'deploy',ROOT/'frontend/dist'):
    for path in [folder,*folder.rglob('*')]:
        if path.is_file():os.chmod(path,0o644)
        elif path.is_dir():os.chmod(path,0o755)
    os.chmod(folder,0o755)
common='NoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\nPrivateTmp=true\n'
exec_args=[str(venv/'bin/uvicorn'),'app:app','--host',str(cfg['listen_host']),'--port',str(cfg['listen_port']),'--ssl-certfile',cfg['tls_cert'],'--ssl-keyfile',cfg['tls_key'],'--workers','1','--limit-concurrency','24','--timeout-keep-alive','5','--no-access-log','--no-proxy-headers']
write_unit('redsec-soc-console.service','[Unit]\nDescription=RedSecSOC investigation console\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=simple\nUser=redsec-console\nGroup=redsec-console\nWorkingDirectory='+str(ROOT/'backend')+'\nEnvironment='+quoted('REDSEC_CONFIG='+str(CONFIG_PATH))+'\nEnvironment=PYTHONDONTWRITEBYTECODE=1\nExecStart='+' '.join(quoted(a) for a in exec_args)+'\nRestart=on-failure\nRestartSec=4\nUMask=0077\n'+common+'PrivateDevices=true\nReadWritePaths='+str(data)+'\nProtectKernelTunables=true\nProtectKernelModules=true\nProtectControlGroups=true\nRestrictSUIDSGID=true\nLockPersonality=true\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\nCapabilityBoundingSet=\nMemoryHigh=384M\nMemoryMax=512M\nTasksMax=80\nCPUQuota=150%\n[Install]\nWantedBy=multi-user.target\n')
if cfg.get('local_metadata',True):
    write_unit('redsec-soc-metadata.service','[Unit]\nDescription=Export local read-only Wazuh metadata\n[Service]\nType=oneshot\nUser=root\nEnvironment='+quoted('REDSEC_CONFIG='+str(CONFIG_PATH))+'\nExecStart=/usr/bin/python3 '+quoted(ROOT/'deploy/refresh_metadata.py')+'\nUMask=0022\nNice=10\n'+common+'ReadWritePaths='+str(metadata)+'\n')
    write_unit('redsec-soc-metadata.timer','[Unit]\nDescription=Refresh RedSecSOC metadata\n[Timer]\nOnBootSec=45s\nOnUnitActiveSec=120s\n[Install]\nWantedBy=timers.target\n')
write_unit('redsec-soc-certificate.service','[Unit]\nDescription=Check or renew configured console certificate\n[Service]\nType=oneshot\nUser=root\nEnvironment='+quoted('REDSEC_CONFIG='+str(CONFIG_PATH))+'\nExecStart=/usr/bin/python3 '+quoted(ROOT/'deploy/renew_certificate.py')+'\nUMask=0077\n')
write_unit('redsec-soc-certificate.timer','[Unit]\nDescription=Check RedSecSOC TLS certificate daily\n[Timer]\nOnBootSec=5m\nOnUnitActiveSec=1d\n[Install]\nWantedBy=timers.target\n')
run('systemctl','daemon-reload')
if cfg.get('local_metadata',True):
    run(sys.executable,str(ROOT/'deploy/refresh_metadata.py'))
    run('systemctl','enable','--now','redsec-soc-metadata.timer')
else:
    run('systemctl','disable','--now','redsec-soc-metadata.timer')
run('systemctl','enable','--now','redsec-soc-certificate.timer','redsec-soc-console.service')
run('systemctl','restart','redsec-soc-console.service')
run('systemctl','is-active','redsec-soc-console.service')
print('RedSecSOC installed. Existing accounts, evidence and configuration preserved. Firewall rules and Wazuh services were not changed.')
