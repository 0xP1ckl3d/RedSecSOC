"""Fail closed on obvious secret/runtime artifacts in the Git publication set."""
import pathlib,re,subprocess,sys
root=pathlib.Path(__file__).resolve().parents[1]
result=subprocess.run(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=root,capture_output=True,check=True)
bad=[];files=[root/p.decode('utf-8') for p in result.stdout.split(b'\0') if p]
for path in files:
    relative=path.relative_to(root).as_posix()
    if path.suffix.lower() in ('.pem','.key','.pfx','.p12','.db','.sqlite','.gz') or path.name in ('config.json','topology.json','setup-credentials.txt','console-access.json','ssh-passwords.json'):bad.append((relative,'runtime or credential artifact'));continue
    if not path.is_file():continue
    # Documentation screenshots require visual review; only bounded PNG assets
    # are accepted here. Pixel content is not covered by text/secret scanning.
    if relative.startswith('docs/images/') and path.suffix.lower()=='.png':
        blob=path.read_bytes()
        if not blob.startswith(b'\x89PNG\r\n\x1a\n') or len(blob)>2000000:bad.append((relative,'invalid or oversized documentation image'))
        continue
    try:text=path.read_text(encoding='utf-8')
    except UnicodeDecodeError:bad.append((relative,'unexpected binary file'));continue
    if re.search(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',text):bad.append((relative,'private key'))
    # Match this deployment's ranges without embedding them as literals here.
    if re.search(r'\b10[.]10[.]10[.]\d+\b|\b192[.]168[.]50[.]\d+\b',text):bad.append((relative,'deployment address leakage'))
    if re.search(r'(?i)(?:password|token|secret)\s*[:=]\s*["\'][A-Za-z0-9_?!+*/-]{24,}["\']',text) and '/tests/' not in '/'+relative:bad.append((relative,'hardcoded secret-shaped value'))
if bad:
    for path,reason in bad:print(path+': '+reason,file=sys.stderr)
    raise SystemExit(1)
print('Publication check passed for '+str(len(files))+' source files; manual review is still required.')
