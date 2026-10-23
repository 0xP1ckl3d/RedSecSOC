"""Configured architecture plus dated observations; no remote network scanner."""
from urllib.parse import urlparse

def build_topology(manifest,observed):
    services=[]
    for entry in manifest.get('services',[]):
        service=dict(entry);snapshot=observed.get(entry.get('observation','services.json'),{})
        unit=snapshot.get('units',{}).get(entry.get('unit'),{})
        service['state']=unit.get('ActiveState','Not observed')
        service['checked_at']=snapshot.get('updated') if unit else None
        service['definition_basis']='Configured inventory'
        service['state_basis']='Dated service-unit observation' if unit else 'No observation supplied'
        service['local_listeners']=snapshot.get('listeners',[]) if entry.get('observation','services.json')=='services.json' else []
        service.setdefault('host','Not configured');service.setdefault('node','Placement not configured')
        service.setdefault('binding','Not configured');service.setdefault('authentication','See deployment configuration')
        service.setdefault('access','See deployment configuration');service.setdefault('purpose','Configured service')
        url=service.get('url')
        if url and (urlparse(url).scheme not in ('http','https') or not urlparse(url).hostname):service['url']=None
        services.append(service)
    nodes=[dict(n) for n in manifest.get('nodes',[])]+[dict(s) for s in services]
    ids={n['id'] for n in nodes}
    flows=[dict(f) for f in manifest.get('flows',[]) if f.get('source_id') in ids and f.get('target_id') in ids]
    return {'services':services,'nodes':nodes,'flows':flows,'configured':bool(manifest),'label':manifest.get('label','Deployment topology not configured'),'discovery':{'automatic':['Current manager agent inventory','Indexed source hosts and record types','Locally exported service-unit status and listeners','Agent-reported current addresses'],'configured':['Remote services, dashboard URLs and deployment placement','Network mirror paths and expected forwarding relationships','External integrations and their authentication descriptions'],'unavailable':['Arbitrary remote VM/service discovery','Verification of configured forwarding from packet counts alone']},'note':'The diagram describes configured architecture. Service status and source evidence are observed separately, with timestamps. Unknown services are never invented. To map another deployment, supply its topology manifest and optional remote status snapshots; the console does not scan the network.'}
