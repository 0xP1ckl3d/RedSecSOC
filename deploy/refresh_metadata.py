"""Root-only scheduled exporter; the web service receives no manager admin access."""
import json
import os
import pathlib
import re
import subprocess
import time
import sqlite3
import ipaddress
import xml.etree.ElementTree as ET

config_path=pathlib.Path(os.environ.get('REDSEC_CONFIG','/etc/redsec-soc-console/config.json'))
config=json.loads(config_path.read_text());wazuh=pathlib.Path(config.get('wazuh_home','/var/ossec'))
target=pathlib.Path(config.get('metadata','/var/lib/redsec-soc-metadata'));target.mkdir(parents=True,exist_ok=True)
rules={};errors=[]
for folder in [wazuh/'ruleset/rules',wazuh/'etc/rules']:
    for path in sorted(pathlib.Path(folder).glob('*.xml')):
        try:
            content=re.sub(r'<\?xml[^>]*\?>','',path.read_text(errors='replace'))
            # Wazuh's XML dialect accepts escaped regex angle brackets inside
            # text nodes. Adapt a copy for a strict XML parser; never edit rules.
            def protect(m):
                body=m.group(2)
                if '<![CDATA[' in body:return m.group(0)
                body=re.sub(r'&(?!#\d+;|#x[0-9a-fA-F]+;|amp;|lt;|gt;|quot;|apos;)','&amp;',body)
                return m.group(1)+body.replace('<','&lt;').replace('>','&gt;')+m.group(3)
            content=re.sub(r'(<(?:field|regex|match|description|list|program_name)\b[^>]*>)(.*?)(</(?:field|regex|match|description|list|program_name)\s*>)',protect,content,flags=re.S)
            root=ET.fromstring('<root>'+content+'</root>')
            for group in root.findall('group'):
                for rule in group.findall('rule'):
                    rid=rule.get('id')
                    if not rid:continue
                    conditions=[{'kind':node.tag,'value':node.text or '',**node.attrib} for node in rule if node.tag not in ('description','mitre','group','info','options')]
                    rules[rid]={'id':rid,'level':rule.get('level'),'description':rule.findtext('description',''),'groups':group.get('name','')+(rule.findtext('group','')),'conditions':conditions,'parents':re.findall(r'\d+',rule.findtext('if_sid','')),'frequency':rule.get('frequency'),'timeframe':rule.get('timeframe'),'source':str(path),'mitre':[x.text for x in rule.findall('mitre/id')],'options':[x.text for x in rule.findall('options')]}
        except Exception as e:errors.append({'file':path.name,'error':type(e).__name__})

def write(name,value):
    temp=target/(name+'.new');temp.write_text(json.dumps(value,ensure_ascii=False));os.chmod(temp,0o644);temp.replace(target/name)

write('catalogue.json',{'updated':time.time(),'rules':rules,'errors':errors})
try:
    p=subprocess.run([str(wazuh/'bin/agent_control'),'-l','-j'],capture_output=True,text=True,timeout=15,check=True)
    inventory=json.loads(p.stdout)
    write('inventory.json',{'updated':time.time(),'inventory':inventory})
except Exception as e:
    write('inventory-error.json',{'updated':time.time(),'error':type(e).__name__})
units={}
for unit in config.get('observed_units',['wazuh-manager','wazuh-indexer','wazuh-dashboard','filebeat','velociraptor','suricata','redsec-soc-console','ssh']):
    if not re.fullmatch(r'[a-zA-Z0-9_.@-]{1,100}',unit):continue
    result=subprocess.run(['systemctl','show',unit+'.service','--property=ActiveState,SubState,Result,LoadState'],capture_output=True,text=True,timeout=5)
    state=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
    if state.get('LoadState')!='not-found':units[unit]=state
listeners=subprocess.run(['ss','-H','-lntu'],capture_output=True,text=True,timeout=5).stdout
write('services.json',{'updated':time.time(),'units':units,'listeners':[{'protocol':line.split()[0],'address':line.split()[4]} for line in listeners.splitlines() if len(line.split())>4]})
try:
    candidates={};now=time.time()
    with sqlite3.connect('file:'+str(wazuh/'queue/db/global.db')+'?mode=ro',uri=True,timeout=2) as db:
        db.row_factory=sqlite3.Row
        db_agents=[dict(r) for r in db.execute('SELECT name,ip,last_keepalive,os_name,os_version FROM agent')]
        for agent in db_agents:
            name,address,seen=agent['name'],agent['ip'],agent['last_keepalive']
            if not address or not seen or now-seen>86400:continue
            try:ip=ipaddress.ip_address(address)
            except ValueError:continue
            if ip.is_loopback or ip.is_unspecified or ip.is_multicast:continue
            candidates.setdefault(str(ip),[]).append({'name':name,'source':'Current Wazuh agent inventory','observed':seen})
    addresses={ip:rows[0] for ip,rows in candidates.items() if len({r['name'] for r in rows})==1}
    # Enrich the existing registration export with agent-reported addresses/OS;
    # never export the internal agent transport key column.
    inventory_file=target/'inventory.json'
    if inventory_file.exists():
        saved=json.loads(inventory_file.read_text());rows=saved.get('inventory',{}).get('data',[])
        if isinstance(rows,list):
            details={a['name']:a for a in db_agents}
            for row in rows:
                detail=details.get(row['name'],{})
                for key in ('ip','os_name','os_version','last_keepalive'):
                    if detail.get(key) is not None:row[key]=detail[key]
            write('inventory.json',saved)
    aliases=pathlib.Path(config.get('asset_aliases_file','/etc/redsec-soc-console/asset-aliases.json'))
    if aliases.exists():
        for address,name in json.loads(aliases.read_text()).items():
            ip=str(ipaddress.ip_address(address));addresses[ip]={'name':name,'source':'Approved infrastructure asset inventory','observed':now}
    write('assets.json',{'updated':now,'addresses':addresses,'ambiguous':[ip for ip,rows in candidates.items() if len({r['name'] for r in rows})>1]})
except Exception as e:
    write('assets-error.json',{'updated':time.time(),'error':type(e).__name__})
print(json.dumps({'rules':len(rules),'parse_errors':errors,'inventory_file':(target/'inventory.json').exists()}))
