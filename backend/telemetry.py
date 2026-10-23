"""Observation checklist. Registration, freshness and detections are separate."""
def windows_event(ids,sysmon=False):
    clauses=[{'terms':{'data.win.system.eventID':[str(i) for i in ids]}}]
    if sysmon:clauses.append({'wildcard':{'data.win.system.channel':{'value':'*Sysmon*','case_insensitive':True}}})
    return {'bool':{'filter':clauses}}

SIGNALS={
 'process_creation':{'label':'Process creation','platform':'Windows','filter':{'bool':{'should':[windows_event([1],True),windows_event([4688])],'minimum_should_match':1}}},
 'authentication':{'label':'Windows authentication','platform':'Windows','filter':windows_event([4624,4625])},
 'powershell_script':{'label':'PowerShell script blocks','platform':'Windows','filter':windows_event([4104])},
 'endpoint_network':{'label':'Sysmon network connections','platform':'Windows','filter':windows_event([3],True)},
 'endpoint_dns':{'label':'Sysmon DNS queries','platform':'Windows','filter':windows_event([22],True)},
 'file_activity':{'label':'Sysmon file operations','platform':'Windows','filter':windows_event([11,15,23,26],True)},
 'registry_activity':{'label':'Sysmon registry operations','platform':'Windows','filter':windows_event([12,13,14],True)},
 'winrm':{'label':'WinRM channel','platform':'Windows','filter':{'wildcard':{'data.win.system.channel':{'value':'*WinRM*','case_insensitive':True}}}},
 'managed_runtime':{'label':'.NET runtime provider','platform':'Windows','filter':{'wildcard':{'data.win.system.providerName':{'value':'*DotNETRuntime*','case_insensitive':True}}}},
 'linux_audit':{'label':'Linux audit records','platform':'Linux','filter':{'exists':{'field':'data.audit.type'}}},
 'file_integrity':{'label':'File integrity observations','platform':'Any','filter':{'exists':{'field':'syscheck.path'}}},
 'container':{'label':'Container lifecycle','platform':'Linux','filter':{'bool':{'should':[{'term':{'data.integration':'redsec_docker'}},{'exists':{'field':'data.docker.Action'}}],'minimum_should_match':1}}},
 'network_sensor':{'label':'Network sensor protocol records','platform':'Any','filter':{'exists':{'field':'data.event_type'}}}
}

def observation_query(start):
    return {'size':0,'query':{'range':{'timestamp':{'gte':start}}},'aggs':{'hosts':{'terms':{'field':'agent.name','size':100},'aggs':{'latest':{'max':{'field':'timestamp'}},'signals':{'filters':{'filters':{k:v['filter'] for k,v in SIGNALS.items()}}}}}}}

def observation_rows(inventory,observations,alerts):
    data=inventory.get('inventory',{})
    agents=data if isinstance(data,list) else data.get('data',{}).get('affected_items',[]) if isinstance(data.get('data'),dict) else data.get('data',data.get('agents',[]))
    if not isinstance(agents,list):agents=[]
    seen={h['key']:h for h in observations.get('aggregations',{}).get('hosts',{}).get('buckets',[])}
    detected={h['key']:h for h in alerts.get('aggregations',{}).get('hosts',{}).get('buckets',[])}
    names=sorted(set(seen)|{a['name'] for a in agents});rows=[]
    for name in names:
        agent=next((a for a in agents if a['name']==name),{});raw=seen.get(name,{});buckets=raw.get('signals',{}).get('buckets',{})
        os_name=agent.get('os_name','');platform='Windows' if 'windows' in os_name.lower() else 'Linux' if any(p in os_name.lower() for p in ('linux','ubuntu','debian','kali')) else 'Unknown'
        checks=[{'id':k,'label':v['label'],'count':buckets.get(k,{}).get('doc_count',0),'status':'Observed' if buckets.get(k,{}).get('doc_count',0)>0 else 'Not observed in this window'} for k,v in SIGNALS.items() if v['platform'] in (platform,'Any') or platform=='Unknown']
        rows.append({'name':name,'registered':bool(agent),'agent_status':agent.get('status','Not registered in manager inventory'),'platform':platform,'raw_count':raw.get('doc_count',0),'latest':raw.get('latest',{}).get('value_as_string'),'signals':checks,'alerts_in_retained_indices':detected.get(name,{}).get('doc_count',0)})
    return rows
