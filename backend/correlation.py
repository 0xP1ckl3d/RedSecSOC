"""Evidence stages and links; stages are observations, never an asserted attack."""
from engine import epoch,relation,flatten,text
from collections import defaultdict
import hashlib
import ipaddress
from datetime import datetime,timezone

BUILTIN={'','0x0','0x3e7','0x3e4','0x3e5'}
BROKERS={'services.exe','svchost.exe','wininit.exe','smss.exe','lsass.exe','explorer.exe','systemd','init'}
IDENTITY_FIELDS={
 'process_guid':['data.win.eventdata.processGuid','data.win.eventdata.sourceProcessGUID','data.win.eventdata.sourceProcessGuid'],
 'parent_guid':['data.win.eventdata.parentProcessGuid'],
 'source_ip':['data.src_ip','data.srcip','data.win.eventdata.sourceIp','data.win.eventdata.ipAddress','source.ip'],
 'destination_ip':['data.dest_ip','data.dstip','data.win.eventdata.destinationIp','destination.ip'],
 'source_port':['data.src_port','data.srcport','data.win.eventdata.sourcePort','data.win.eventdata.ipPort','source.port'],
 'destination_port':['data.dest_port','data.dstport','data.win.eventdata.destinationPort','destination.port'],
 'protocol':['data.proto','data.win.eventdata.protocol','network.transport'],
 'logon_id':['data.win.eventdata.logonId','data.win.eventdata.targetLogonId','data.win.eventdata.subjectLogonId'],
 'logon_guid':['data.win.eventdata.logonGuid'],'logon_type':['data.win.eventdata.logonType'],
 'script_block_id':['data.win.eventdata.scriptBlockId'],'audit_id':['data.audit.id'],
 'observed_time':['data.win.eventdata.utcTime','data.win.system.systemTime','data.timestamp','timestamp'],
 'flow_start':['data.flow.start'],'flow_end':['data.flow.end'],
 'agent.name':['agent.name'],'agent.ip':['agent.ip']}

def identity_sources(source):
    flat=flatten(source)
    return {key:{'field':field,'value':flat[field]} for key,fields in IDENTITY_FIELDS.items() for field in [next((f for f in fields if text(flat.get(f)).strip() not in ('','-')),None)] if field}

def ip_key(value):
    try:
        ip=ipaddress.ip_address(value)
        return str(ip.ipv4_mapped or ip) if ip.version==6 else str(ip)
    except ValueError:return ''

def clock(value):
    try:
        stamp=datetime.fromisoformat(str(value).replace('Z','+00:00'))
        return (stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)).timestamp()
    except (ValueError,TypeError):return 0

def event_clock(e):return clock(e['identity'].get('observed_time')) or clock(e['time'])

def tuple_key(e):
    i=e['identity'];values=(ip_key(i.get('source_ip','')),str(i.get('source_port','')),ip_key(i.get('destination_ip','')),str(i.get('destination_port','')),str(i.get('protocol','')).lower())
    return values if all(values) else None

def clocks_overlap(a,b):
    # Use recorded flow lifetime when available; ingestion time is a fallback.
    def span(e):
        i=e['identity'];point=event_clock(e)
        return (clock(i.get('flow_start')) or point,clock(i.get('flow_end')) or point)
    sa,ea=span(a);sb,eb=span(b)
    return sa<=eb+5 and sb<=ea+5

def evidence_links(events,seed=None,truncated=False):
    """Build components from recorded identities, never shared IP/time alone.

    Edges are evidence associations. A network-logon association is explicitly
    not proof that the source process caused execution on the destination.
    """
    unique={e['key']:e for e in events};events=list(unique.values())[:700]
    nodes={e['key']:e for e in events};edges=[];seen=set();indexes=defaultdict(list)
    def link(a,b,kind,basis,fields):
        pair=(min(a['key'],b['key']),max(a['key'],b['key']),kind)
        if a['key']==b['key'] or pair in seen:return
        proof_keys=set(fields)|{'agent.name','agent.ip','observed_time','flow_start','flow_end','logon_guid','logon_type'}
        if kind=='parent':proof_keys|={'process_guid','parent_guid'}
        support=[{'ref':e['ref'],'fields':[v for k,v in e.get('identity_sources',{}).items() if k in proof_keys]} for e in (a,b)]
        seen.add(pair);edges.append({'source':a['key'],'target':b['key'],'kind':kind,'basis':basis,'fields':fields,'source_ref':a['ref'],'target_ref':b['ref'],'support':support})
    for e in events:
        i=e['identity'];h=e['host']
        for name in ('process_guid','script_block_id','audit_id'):
            if i.get(name) and h:indexes[(name,h,i[name])].append(e)
        session=str(i.get('logon_id','')).lower()
        if session not in BUILTIN and h:indexes[('logon_id',h,session)].append(e)
    for (name,h,value),group in indexes.items():
        known_guids={e['identity'].get('logon_guid') for e in group}-{None,''} if name=='logon_id' else set()
        anchor=next((e for e in group if e['family']=='Process creation'),group[0]) if name=='process_guid' else next((e for e in group if e['event_id']=='4624'),group[0])
        for e in group:
            # Logon IDs are host-local and can recur after a reboot. This query
            # is bounded in time; incompatible nonzero Logon GUIDs still reject.
            if name=='logon_id':
                a,b=anchor['identity'].get('logon_guid'),e['identity'].get('logon_guid')
                if a and b and a!=b:continue
                if len(known_guids)>1 and (not a or not b):continue
                if abs(event_clock(anchor)-event_clock(e))>7200:continue
            link(anchor,e,'session' if name=='logon_id' else 'identifier','Same host and recorded '+name.replace('_',' '),[name,'agent.name'])
    for e in events:
        i=e['identity']
        if e['family']=='Process creation' and 'sysmon' in e['channel'].lower() and i.get('parent_guid'):
            parents=indexes.get(('process_guid',e['host'],i['parent_guid']),[])
            parent=next((p for p in parents if p['family']=='Process creation'),parents[0] if parents else None)
            if parent and parent['identity'].get('image','').replace('\\','/').rsplit('/',1)[-1].lower() not in BROKERS:link(parent,e,'parent','Recorded parent Process GUID → child Process GUID',['process_guid','parent_guid','agent.name'])
    flows=defaultdict(list)
    for e in events:
        key=tuple_key(e)
        if key:
            reverse=(key[2],key[3],key[0],key[1],key[4]);flows[min(key,reverse)].append(e)
    for group in flows.values():
        # A spanning set records the basis without a quadratic clique of every
        # duplicate sensor update. Prefer an endpoint process as the anchor.
        group.sort(key=lambda e:(not bool(e['identity'].get('process_guid')),event_clock(e)))
        for n,a in enumerate(group):
            b=next((b for b in group[:n] if clocks_overlap(a,b)),None)
            if b:link(b,a,'flow','Complete 5-tuple and overlapping recorded time; flow association',['source_ip','source_port','destination_ip','destination_port','protocol','observed_time / flow_start / flow_end'])
    connections=[e for e in events if e['family']=='Network connection' and e['identity'].get('process_guid') and tuple_key(e)]
    for auth in (e for e in events if e['event_id']=='4624' and e['identity'].get('logon_type') in ('3','10') and e['identity'].get('logon_id','').lower() not in BUILTIN):
        ai=auth['identity']
        for connection in connections:
            ci=connection['identity']
            if ci.get('initiated')!='true' or ip_key(connection.get('agent_ip',''))!=ip_key(ci['source_ip']) or connection['host']==auth['host'] or ci['protocol']!='tcp' or ci['destination_port'] not in ('445','135','5985','5986','3389'):continue
            if not ai.get('source_port') or ai['source_port']=='0':continue
            if ip_key(ci['destination_ip'])!=ip_key(auth.get('agent_ip','')) or not ip_key(auth.get('agent_ip','')):continue
            if ip_key(ci['source_ip'])!=ip_key(ai.get('source_ip','')) or ci['source_port']!=ai['source_port'] or abs(event_clock(connection)-event_clock(auth))>10:continue
            link(connection,auth,'remote-session','Destination host IP, source IP/port, remote-service port and network logon within 10 s; candidate session association',['agent.ip','source_ip','source_port','destination_ip','destination_port','logon_id','logon_type','observed_time'])
    adjacency=defaultdict(set)
    for edge in edges:adjacency[edge['source']].add(edge['target']);adjacency[edge['target']].add(edge['source'])
    components=[];visited=set()
    for key in adjacency:
        if key in visited:continue
        component=set();frontier=[key]
        while frontier:
            current=frontier.pop()
            if current in component:continue
            component.add(current);frontier.extend(adjacency[current]-component)
        visited.update(component);members=[nodes[k] for k in component];ce=[e for e in edges if e['source'] in component and e['target'] in component]
        stages=sorted({stage(e) for e in members}-{None});processes=sorted({e['host']+'|'+e['identity']['process_guid'] for e in members if e['identity'].get('process_guid')})
        stable=processes or sorted(component)
        components.append({'id':hashlib.sha256('|'.join(stable).encode()).hexdigest(),'candidate':len(stages)>=2,'event_keys':sorted(component),'hosts':sorted({e['host'] for e in members}),'stages':stages,'edges':ce,'processes':len(processes),'first':min(members,key=event_clock)['time'],'last':max(members,key=event_clock)['time'],'cross_host':any(e['kind']=='remote-session' for e in ce),'status':'Evidence-linked candidate; analyst review required'})
    selected=next((c for c in components if seed and seed['key'] in c['event_keys']),None)
    linked=set(selected['event_keys']) if selected else {seed['key']} if seed else set()
    return {'components':components,'selected':selected,'linked_keys':sorted(linked),'edges':selected['edges'] if selected else edges if not seed else [],'partial':truncated or len(unique)>700,'loaded':len(events),'notice':'Identifiers establish process/session/flow associations, not malicious intent. Remote-session edges require target-host IP, exact source port/IP and close event time; even these do not prove remote execution causation. Unlinked time/address context is excluded. Missing records, NAT, clock skew, logon-ID reuse or collection gaps can prevent reconstruction.'}

STAGES=[('authentication','Authentication / remote session'),('process','Process execution'),('managed_runtime','Managed runtime / assembly telemetry'),('network','Network communication'),('objects','File / registry activity')]

def stage(event):
    eid=event['event_id'];family=event['family'];channel=event['channel'].lower()
    if family=='Authentication' or family=='Remote management' or 'winrm' in channel:return 'authentication'
    if family=='Process creation':return 'process'
    if ('dotnet' in channel or '.netruntime' in channel or 'dotnetruntime' in event.get('provider','').lower() or family=='Managed runtime'):return 'managed_runtime'
    # Sysmon DLL/ImageLoad telemetry is not equivalent to a managed assembly.
    if family in ('Network connection','Network detection','Network activity','DNS'):return 'network'
    if family in ('File creation','File deletion','File integrity','Registry','Registry activity'):return 'objects'
    return None

def evidence_sequence(seed,events,truncated=False):
    found={key:[] for key,label in STAGES}
    for event in events:
        key=stage(event)
        if key:
            r=relation(seed,event)
            found[key].append({'ref':event['ref'],'host':event['host'],'time':event['time'],'title':event['title'],'subject':event['subject'],'relation':r,'event_id':event['event_id']})
    stages=[]
    for key,label in STAGES:
        rows=sorted(found[key],key=lambda e:epoch(e['time']))
        strong=[e for e in rows if e['relation']['strength'] in ('identifier','session','flow')]
        stages.append({'id':key,'label':label,'status':'Linked evidence observed' if strong else 'Context observed' if rows else 'Not observed in retrieved evidence','observations':rows[:30],'count':len(rows),'linked_count':len(strong),'truncated':len(rows)>30})
    return {'stages':stages,'partial':truncated,'notice':'This is an evidence-stage view, not a confirmed attack chain or execution order. Links name their source identifiers/session/flow basis; time or address context alone does not establish causation. Missing stages mean not observed in this bounded retrieval, never confirmed inactivity. Image-load records do not prove a .NET assembly execution.'}
