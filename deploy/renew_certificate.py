"""Optional local-CA renewal, or expiry checking for operator-managed TLS."""
import json,os,pathlib,subprocess,tempfile,secrets,ipaddress
cfg=json.loads(pathlib.Path(os.environ.get('REDSEC_CONFIG','/etc/redsec-soc-console/config.json')).read_text())
cert=pathlib.Path(cfg['tls_cert']);key=pathlib.Path(cfg['tls_key'])
result=subprocess.run(['openssl','x509','-checkend','2592000','-noout','-in',str(cert)],capture_output=True)
if result.returncode==0:raise SystemExit(0)
renewal=cfg.get('certificate_renewal',{})
if not renewal.get('ca_key'):
    raise SystemExit('TLS certificate expires within 30 days. Renew it using the deployment certificate provider; no CA signing key was configured.')
# The CA signing key stays outside the web-service account and repository.
with tempfile.TemporaryDirectory(prefix='redsec-cert-') as folder:
    folder=pathlib.Path(folder);os.chmod(folder,0o700)
    sans=[]
    for name in renewal['sans']:
        try:ipaddress.ip_address(name);prefix='IP:'
        except ValueError:prefix='DNS:'
        if any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.:-_' for c in name):raise ValueError('Invalid certificate SAN')
        sans.append(prefix+name)
    (folder/'ext.cnf').write_text('subjectAltName='+','.join(sans)+'\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
    subprocess.run(['openssl','req','-new','-newkey','rsa:3072','-nodes','-subj','/CN=RedSecSOC','-keyout',str(folder/'key'),'-out',str(folder/'csr')],check=True,capture_output=True)
    subprocess.run(['openssl','x509','-req','-in',str(folder/'csr'),'-CA',renewal['ca_cert'],'-CAkey',renewal['ca_key'],'-set_serial',str(secrets.randbits(150)),'-days','397','-sha256','-extfile',str(folder/'ext.cnf'),'-out',str(folder/'cert')],check=True,capture_output=True)
    for src,dst in [('key',key),('cert',cert)]:
        tmp=dst.with_suffix('.new');tmp.write_bytes((folder/src).read_bytes());os.chmod(tmp,0o640);subprocess.run(['chown','root:redsec-console',str(tmp)],check=True);tmp.replace(dst)
subprocess.run(['systemctl','try-restart','redsec-soc-console.service'],check=True)
