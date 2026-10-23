"""Stable recurrence summaries, traffic observations and explicit analyst policy."""
import hashlib
import ipaddress
import json
import re
from engine import flatten,text
from addresses import classify_address

FIELDS={
 'rule':['rule.id'],
 'host':['agent.name'],
 'object':['syscheck.path','data.win.eventdata.targetFilename','data.win.eventdata.targetObject','file.path'],
 'signature':['data.alert.signature'],
 'check':['data.sca.check.title'],
 'image':['data.win.eventdata.image','data.audit.exe','process.executable'],
 'destination_ip':['data.dest_ip','data.dstip','data.win.eventdata.destinationIp','destination.ip'],
 'destination_port':['data.dest_port','data.dstport','data.win.eventdata.destinationPort','destination.port'],
 'source_ip':['data.src_ip','data.srcip','data.win.eventdata.sourceIp','source.ip'],
 'user':['data.win.eventdata.user','data.audit.auid','user.name'],
 'command':['data.win.eventdata.commandLine','data.audit.command','process.command_line'],
 'sha256':['syscheck.sha256_after','file.hash.sha256'],
 'protocol':['data.app_proto','data.proto','data.win.eventdata.protocol','network.transport'],
 'probe_prefix':['data.win.eventdata.targetFilename']
}

def policy_key(kind,criteria):
    return hashlib.sha256(json.dumps({'kind':kind,'criteria':criteria},sort_keys=True,separators=(',',':')).encode()).hexdigest()

def validate_criteria(kind,criteria):
    allowed={'alert-rule':{'rule','host','object','signature','check','image','user','command','sha256','probe_prefix','source_ip','destination_ip','destination_port','protocol'},'network-destination':{'destination_ip','destination_port','source_ip','protocol'}}
    if kind not in allowed or not isinstance(criteria,dict) or not criteria or set(criteria)-allowed[kind]:raise ValueError('Unsupported pattern scope')
    cleaned={k:str(v).strip() for k,v in criteria.items() if str(v).strip()}
    if any(len(v)>1000 for v in cleaned.values()):raise ValueError('Pattern scope is too long')
    if kind=='alert-rule' and not cleaned.get('rule','').isdigit():raise ValueError('A native detection rule is required')
    if cleaned.get('sha256') and not re.fullmatch(r'[a-fA-F0-9]{64}',cleaned['sha256']):raise ValueError('Use the exact 64-digit recorded SHA-256')
    if cleaned.get('probe_prefix'):
        from assessment import windows_path
        prefix=windows_path(cleaned['probe_prefix'])
        if cleaned.get('rule')!='92213' or not prefix.endswith('/temp/__psscriptpolicytest_') or any(c in prefix for c in '*?'):raise ValueError('The policy-test template requires rule 92213 and an exact Temp directory prefix')
        image=windows_path(cleaned.get('image',''))
        if image not in ('c:/windows/system32/windowspowershell/v1.0/powershell.exe','c:/windows/syswow64/windowspowershell/v1.0/powershell.exe','c:/windows/system32/wsmprovhost.exe') and not re.fullmatch(r'c:/program files/powershell/\d+(?:\.\d+)*/pwsh\.exe',image):raise ValueError('The policy-test template requires an expected recorded PowerShell creator path')
    if kind=='network-destination':
        if not cleaned.get('destination_ip'):raise ValueError('A destination IP is required')
    for field in ('destination_ip','source_ip'):
        if cleaned.get(field):cleaned[field]=str(ipaddress.ip_address(cleaned[field]))
    if 'destination_port' in cleaned:
        try:port=int(cleaned['destination_port'])
        except ValueError:raise ValueError('Invalid destination port')
        if not 1<=port<=65535:raise ValueError('Invalid destination port')
        cleaned['destination_port']=str(port)
    return cleaned

def validate_safe(kind,criteria):
    """Safe is deliberately more constrained than a Suspicious watch scope."""
    c=validate_criteria(kind,criteria)
    if kind=='network-destination':
        if not all(c.get(k) for k in ('destination_ip','source_ip','destination_port','protocol')):raise ValueError('Safe network scopes require source, destination, port and protocol; an IP alone is insufficient')
    elif not c.get('host'):raise ValueError('Safe detection scopes require an exact host')
    elif c.get('check'):pass
    elif c.get('signature'):
        if not all(c.get(k) for k in ('source_ip','destination_ip','destination_port','protocol')):raise ValueError('Safe sensor signatures also require source, destination, port and protocol; changed traffic must remain visible')
    elif c.get('probe_prefix') and c.get('image') and c.get('user'):pass
    elif c.get('object') and (c.get('sha256') or all(c.get(k) for k in ('image','user','command'))):pass
    else:raise ValueError('Safe requires a host and a verified signature/check, policy-test template with creator/user, or exact object with checksum or creator/user/command. A whole rule or directory cannot be marked Safe')
    return c

def probe_regex(prefix):
    # Same expression in Python and Lucene regexp: a generated basename only,
    # no nested directories, executable suffixes or arbitrary wildcard paths.
    literal=''.join('\\'+c if c in '.?+*|{}[]()"\\#@&<>~' else c for c in prefix)
    return literal+r'[^/\\]+\.ps(m)?1'

def suggested_scope(event,source):
    f=flatten(source);c={'rule':event['rule_id'],'host':event['host']}
    if event.get('assessment',{}).get('pattern')=='powershell-policy-probe' and event['rule_id']=='92213':
        path=text(f.get('data.win.eventdata.targetFilename'));match=re.search('__psscriptpolicytest_',path,re.I)
        if match and event['identity'].get('user'):c.update(probe_prefix=path[:match.end()],image=event['identity']['image'],user=event['identity']['user'])
    else:
        for k in ('object','signature','check','image','user','command','sha256','source_ip','destination_ip','destination_port','protocol'):
            value=next((text(f.get(field)) for field in FIELDS[k] if f.get(field)),None)
            if value:c[k]=value
    return c

def scope_query(policy):
    clauses=[]
    for key,value in policy['criteria'].items():
        if key=='probe_prefix':
            clauses += [{'term':{'data.win.system.eventID':'11'}},{'term':{'data.win.system.channel':'Microsoft-Windows-Sysmon/Operational'}},{'regexp':{FIELDS[key][0]:{'value':probe_regex(value),'max_determinized_states':10000}}}]
            continue
        values=[value]
        if key in ('source_ip','destination_ip'):
            ip=ipaddress.ip_address(value)
            if ip.version==6:values=list(set([ip.compressed,ip.exploded,ip.compressed.upper(),ip.exploded.upper()]))
        choices=[{'terms':{field:values}} for field in FIELDS[key]]
        clauses.append(choices[0] if len(choices)==1 else {'bool':{'should':choices,'minimum_should_match':1}})
    return {'bool':{'filter':clauses}}

def matches(policy,source):
    flat=flatten(source)
    def equal(key,actual,expected):
        if key=='probe_prefix':return text(flat.get('data.win.system.eventID'))=='11' and text(flat.get('data.win.system.channel'))=='Microsoft-Windows-Sysmon/Operational' and bool(re.fullmatch(probe_regex(expected),text(actual)))
        if key in ('source_ip','destination_ip'):
            try:return ipaddress.ip_address(text(actual))==ipaddress.ip_address(expected)
            except ValueError:return False
        return text(actual)==expected
    return all(any(equal(key,flat.get(field),value) for field in FIELDS[key]) for key,value in policy['criteria'].items())

def decision_for(source,policies):
    matched=[p for p in policies if matches(p,source)]
    if not matched:return None
    # A suspicious mark overrides a safe mark, even if the safe scope is broader.
    matched.sort(key=lambda p:(p['classification']!='Suspicious',-len(p['criteria']),-p['updated']))
    winner=matched[0]
    return {k:winner[k] for k in ('id','kind','criteria','classification','rationale','actor','updated')}|{'matched_policies':len(matched)}

def changed_scopes(source,policies):
    """A near match is visible context, never a safe decision or a verdict."""
    changed=[]
    for p in policies:
        if p['classification']!='Safe' or matches(p,source):continue
        anchor={k:v for k,v in p['criteria'].items() if k in ('rule','host','destination_ip','source_ip')}
        if not anchor or not matches({'criteria':anchor},source):continue
        fields=[k for k,v in p['criteria'].items() if not matches({'criteria':{k:v}},source)]
        changed.append({'id':p['id'],'changed_fields':fields,'rationale':p['rationale']})
    return changed[:5]

def policy_filter(policies):
    safe=[scope_query(p) for p in policies if p['classification']=='Safe'];suspicious=[scope_query(p) for p in policies if p['classification']=='Suspicious']
    if not safe:return None
    return {'bool':{'should':[{'bool':{'must_not':[{'bool':{'should':safe,'minimum_should_match':1}}]}}]+suspicious,'minimum_should_match':1}}

def alert_summary_query(filters,limit=100):
    return {'size':0,'query':{'bool':{'filter':filters}},'aggs':{'patterns':{'terms':{'field':'rule.id','size':limit,'order':{'_count':'desc'}},'aggs':{
        'latest':{'top_hits':{'size':1,'sort':[{'timestamp':'desc'}],'_source':['rule','agent','data','syscheck','timestamp','id','manager','decoder']}},
        'hosts':{'terms':{'field':'agent.name','size':50}},
        'objects':{'terms':{'field':'syscheck.path','size':20}},
        'signatures':{'terms':{'field':'data.alert.signature','size':10}},
        'checks':{'terms':{'field':'data.sca.check.title','size':10}},
        'max_level':{'max':{'field':'rule.level'}},'first':{'min':{'field':'timestamp'}},'last':{'max':{'field':'timestamp'}}
    }}}}

def recurrence_summary(event,source):
    """Stable activity key excludes changing checksums, timestamps and counters."""
    f=flatten(source);identity=event['identity']
    criteria={'rule':event['rule_id'],'family':event['family']}
    target=text(f.get('syscheck.path') or f.get('data.win.eventdata.targetFilename') or f.get('data.win.eventdata.targetObject') or f.get('data.sca.check.id') or f.get('data.sca.check.title'))
    criteria.update(object=target,image=identity.get('image',''),command=identity.get('command',''),user=identity.get('user',''))
    if not target and not criteria['image'] and not criteria['command']:criteria['category']=event['family']
    return policy_key('recurrence',criteria),criteria

def traffic_query(filters,limit=40):
    return {'size':0,'query':{'bool':{'filter':filters+[{'term':{'data.event_type':'flow'}},{'exists':{'field':'data.dest_ip'}}]}},'aggs':{'destinations':{'terms':{'field':'data.dest_ip','size':limit},'aggs':{
        'sources':{'terms':{'field':'data.src_ip','size':25}},'source_count':{'cardinality':{'field':'data.src_ip'}},
        'ports':{'terms':{'field':'data.dest_port','size':20}},'protocols':{'terms':{'field':'data.app_proto','size':15}},
        'collectors':{'terms':{'field':'agent.name','size':10}},'flow_count':{'cardinality':{'field':'data.flow_id'}},
        'to_server':{'sum':{'script':{'lang':'painless','source':"if (!doc.containsKey('data.flow.bytes_toserver') || doc['data.flow.bytes_toserver'].size()==0) return 0; def v=doc['data.flow.bytes_toserver'].value; try {return Double.parseDouble(v.toString());} catch (Exception e) {return 0;}"}}},
        'to_client':{'sum':{'script':{'lang':'painless','source':"if (!doc.containsKey('data.flow.bytes_toclient') || doc['data.flow.bytes_toclient'].size()==0) return 0; def v=doc['data.flow.bytes_toclient'].value; try {return Double.parseDouble(v.toString());} catch (Exception e) {return 0;}"}}},
        'bytes_records':{'filter':{'bool':{'should':[{'exists':{'field':'data.flow.bytes_toserver'}},{'exists':{'field':'data.flow.bytes_toclient'}}],'minimum_should_match':1}}},
        'first':{'min':{'field':'timestamp'}},'last':{'max':{'field':'timestamp'}},
        'sample':{'top_hits':{'size':1,'sort':[{'timestamp':'desc'}],'_source':['timestamp','agent','data','decoder','id','manager']}}
    }},'talkers':{'terms':{'field':'data.src_ip','size':20},'aggs':{'destinations':{'cardinality':{'field':'data.dest_ip'}},'ports':{'cardinality':{'field':'data.dest_port'}},'last':{'max':{'field':'timestamp'}}}}}}

def server_names_query(filters,ips):
    return {'size':0,'query':{'bool':{'filter':filters+[{'terms':{'data.dest_ip':ips}}]}},'aggs':{'destinations':{'terms':{'field':'data.dest_ip','size':len(ips)},'aggs':{'sni':{'terms':{'field':'data.tls.sni','size':10}},'http':{'terms':{'field':'data.http.hostname','size':10}},'signatures':{'terms':{'field':'data.alert.signature','size':5}}}}}}

def address_context(address,assets):
    node=assets.get('addresses',{}).get(address,{})
    return {'ip':address,'name':node.get('name',''),'label':node.get('name') or address,'basis':node.get('source','IP address; no verified asset name'),**classify_address(address),'service_hint':'SSDP multicast group; verify UDP destination port 1900' if address=='239.255.255.250' else ''}
