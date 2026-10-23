import asyncio
import base64
import hashlib
import hmac
import json
import os
import pathlib
import re
import secrets
import time
from collections import OrderedDict, defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from urllib.parse import urlparse
from pydantic import BaseModel, Field

from engine import VERSION, decoded_literals, epoch, normalize as normalize_base, process_graph, relation, script_fragments,focus_evidence
from network import enrich_network
from indexer import Indexer, IndexerError
from store import ROLES, STATUSES, Store, StateConflict
from topology import build_topology
from search import terms_query,network_filter,protocol_filter,port_filter
from assessment import assess,group_events,grouping_signature
from correlation import evidence_sequence,evidence_links,tuple_key,identity_sources
from telemetry import observation_query,observation_rows
from patterns import decision_for,policy_filter,scope_query,alert_summary_query,traffic_query,server_names_query,address_context,recurrence_summary,changed_scopes,suggested_scope,validate_safe
from dashboard import alert_dashboard_query,raw_dashboard_query

ROOT=pathlib.Path(__file__).resolve().parent.parent
CONFIG=json.loads(pathlib.Path(os.environ.get('REDSEC_CONFIG','/etc/redsec-soc-console/config.json')).read_text())
store=Store(CONFIG['database'])
indexer=Indexer(CONFIG)
META=pathlib.Path(CONFIG.get('metadata','/var/lib/redsec-soc-metadata'))
FRONT=pathlib.Path(CONFIG.get('frontend',str(ROOT/'frontend'/'dist')))
cache=OrderedDict()
failures=defaultdict(list)
auth_gate=asyncio.Semaphore(2)
origins=set(CONFIG['origins'])


@asynccontextmanager
async def lifespan(app):
    yield


app=FastAPI(title='RedSec SOC',version=VERSION,docs_url=None,redoc_url=None,openapi_url=None,lifespan=lifespan)
app.add_middleware(TrustedHostMiddleware,allowed_hosts=list({urlparse(o).hostname for o in origins}|{'127.0.0.1','localhost'}))


@app.middleware('http')
async def safeguards(request,call_next):
    if request.method in ('POST','PUT','PATCH','DELETE'):
        if request.headers.get('origin') not in origins:
            return JSONResponse({'detail':'A trusted same-origin request is required'},status_code=403)
        try:size=int(request.headers.get('content-length','0'))
        except ValueError:size=9999999
        if size>300000:return JSONResponse({'detail':'Request is too large'},status_code=413)
        # Content-Length alone is insufficient for chunked bodies.
        chunks=[];total=0
        async for chunk in request.stream():
            total+=len(chunk)
            if total>300000:return JSONResponse({'detail':'Request is too large'},status_code=413)
            chunks.append(chunk)
        request._body=b''.join(chunks)
    response=await call_next(request)
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Referrer-Policy']='no-referrer'
    response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    response.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()'
    response.headers['Strict-Transport-Security']='max-age=31536000'
    if request.url.path.startswith('/api/'):
        response.headers['Cache-Control']='no-store'
    return response


def user(request:Request):
    actor=store.session(request.cookies.get('redsec_session'))
    if not actor:raise HTTPException(401,'Sign in to continue')
    if request.method in ('POST','PUT','PATCH','DELETE'):
        if not hmac.compare_digest(request.headers.get('x-csrf-token',''),actor['csrf']):raise HTTPException(403,'Invalid request token')
    return actor


def analyst(actor=Depends(user)):
    if actor['role'] not in ('admin','analyst'):raise HTTPException(403,'Analyst permission is required')
    return actor


def admin(actor=Depends(user)):
    if actor['role']!='admin':raise HTTPException(403,'Administrator permission is required')
    return actor


@app.exception_handler(IndexerError)
async def indexer_error(request,exc):return JSONResponse({'detail':str(exc)},status_code=503)


@app.exception_handler(ValueError)
async def value_error(request,exc):return JSONResponse({'detail':str(exc)},status_code=400)


@app.exception_handler(StateConflict)
async def state_conflict(request,exc):return JSONResponse({'detail':str(exc)},status_code=409)


@app.exception_handler(PermissionError)
async def permission_error(request,exc):return JSONResponse({'detail':str(exc)},status_code=403)


class Login(BaseModel):
    name:str=Field(min_length=1,max_length=80)
    password:str=Field(min_length=1,max_length=512)


@app.post('/api/login')
async def login(body:Login,request:Request,response:Response):
    now=time.time();address=request.client.host if request.client else 'unknown'
    # Per-account and per-address bounds, expired entries evicted.
    for k in list(failures):
        failures[k]=[t for t in failures[k] if now-t<300]
        if not failures[k]:del failures[k]
    keys=['ip:'+address,'user:'+body.name.lower()]
    if len(failures)>2000 or any(len(failures[k])>=8 for k in keys):raise HTTPException(429,'Too many attempts. Retry in five minutes.')
    async with auth_gate:
        actor=await asyncio.to_thread(store.login,body.name,body.password)
    if not actor:
        for k in keys:failures[k].append(now)
        raise HTTPException(401,'Incorrect username or password')
    for k in keys:failures.pop(k,None)
    response.set_cookie('redsec_session',actor.pop('token'),max_age=28800,httponly=True,secure=True,samesite='strict',path='/')
    return actor


@app.get('/api/me')
def me(actor=Depends(user)):return actor|{'version':VERSION,'statuses':STATUSES}


@app.get('/api/deployment')
def deployment(actor=Depends(user)):
    links=CONFIG.get('links',{})
    return {'label':CONFIG.get('site_label','Security operations'),'links':{k:v for k,v in links.items() if urlparse(v).scheme in ('http','https') and urlparse(v).hostname}}


@app.post('/api/logout')
def logout(request:Request,response:Response,actor=Depends(user)):
    store.logout(request.cookies.get('redsec_session',''));response.delete_cookie('redsec_session',path='/');return {'ok':True}


def metadata(name):
    path=META/name
    key='metadata:'+name
    stamp=path.stat().st_mtime if path.exists() else 0
    if key in cache and cache[key][0]==stamp:return cache[key][1]
    value=json.loads(path.read_text()) if stamp else {}
    cache[key]=(stamp,value)
    return value


def normalize(hit):
    source=hit.get('_source',hit)
    event=assess(enrich_network(normalize_base(hit),source,metadata('assets.json')),source)
    event['provider']=source.get('data',{}).get('win',{}).get('system',{}).get('providerName','')
    event['identity_sources']=identity_sources(source)
    event['pattern_decision']=decision_for(source,active_policies())
    event['changed_safe_scopes']=changed_scopes(source,active_policies())
    return event


def active_policies():
    key='pattern-policy-cache'
    if key not in cache or time.time()-cache[key][0]>3:cache[key]=(time.time(),store.pattern_policies())
    return cache[key][1]


def time_filter(start,end,max_days=31):
    try:
        a=datetime.fromisoformat(start.replace('Z','+00:00'));b=datetime.fromisoformat(end.replace('Z','+00:00'))
        if not a.tzinfo or not b.tzinfo:raise ValueError()
    except (ValueError,AttributeError):raise ValueError('Use timezone-aware start and end timestamps')
    if a>=b or b-a>timedelta(days=max_days):raise ValueError(f'Select an increasing window of at most {max_days} days')
    return {'range':{'timestamp':{'gte':a.isoformat(),'lte':b.isoformat()}}}


async def search_text(q):
    fields=await asyncio.to_thread(indexer.search_fields)
    return terms_query(q,fields,metadata('assets.json'))


def state_query(status):
    with store.db() as db:
        db.execute('CREATE TABLE IF NOT EXISTS event_refs(key TEXT PRIMARY KEY,source_index TEXT NOT NULL,source_id TEXT NOT NULL)')
        rows=db.execute('SELECT r.*,s.status FROM event_refs r JOIN states s ON r.key=s.key').fetchall()
    exclude=status in ('New','Active')
    chosen=[r for r in rows if (r['status'] not in ('New','Investigating') if status=='Active' else r['status']!='New' if status=='New' else r['status']==status)]
    grouped=defaultdict(list)
    for row in chosen:grouped[row['source_index']].append(row['source_id'])
    clauses=[{'bool':{'filter':[{'term':{'_index':index}},{'ids':{'values':ids}}]}} for index,ids in grouped.items()]
    matched={'bool':{'should':clauses,'minimum_should_match':1}} if clauses else {'match_none':{}}
    return {'bool':{'must_not':[matched]}} if exclude else matched


def attach_state(events):
    states=store.states([e['key'] for e in events])
    for e in events:e['state']=states.get(e['key'],{'status':'New','assignee':''})
    return events


async def queue_filters(start,end,kind,q,host,status,category='',protocol='',port=None,include_safe=False,record_type='',review='',maximum=None,rule_id='',source_ip='',destination_ip=''):
    filters=[time_filter(start,end)]
    if host:filters.append({'term':{'agent.name':host}})
    if maximum is not None:filters.append({'range':{'rule.level':{'lte':maximum}}})
    if rule_id:filters.append({'term':{'rule.id':rule_id}})
    if source_ip or destination_ip:
        from patterns import validate_criteria
        if source_ip:
            cleaned=validate_criteria('network-destination',{'destination_ip':source_ip});filters.append(scope_query({'criteria':{'source_ip':cleaned['destination_ip']}}))
        if destination_ip:filters.append(scope_query({'criteria':validate_criteria('network-destination',{'destination_ip':destination_ip})}))
    if category=='network' or protocol or port:filters.append(network_filter())
    if protocol:filters.append(protocol_filter(protocol))
    if port:filters.append(port_filter(port))
    if record_type:filters.append({'term':{'data.event_type':record_type}})
    if q:filters.append(await search_text(q))
    if status and kind=='alerts':
        if status not in (*STATUSES,'Active'):raise ValueError('Invalid disposition')
        filters.append(state_query(status))
    if kind=='alerts' and not include_safe and review!='Safe':
        scope=policy_filter(active_policies())
        if scope:filters.append(scope)
    if review in ('Safe','Suspicious'):filters.append(policy_aggregations()[review.lower()]['filter'])
    if review=='Changed':
        nearby=[]
        for p in active_policies():
            if p['classification']!='Safe':continue
            anchor={k:v for k,v in p['criteria'].items() if k in ('rule','host','source_ip','destination_ip')}
            nearby.append({'bool':{'filter':[scope_query({'criteria':anchor})],'must_not':[scope_query(p)]}})
        filters.append({'bool':{'should':nearby,'minimum_should_match':1}} if nearby else {'match_none':{}})
    return filters


@app.get('/api/queue')
async def queue(start:str,end:str,kind:str=Query('alerts',pattern='^(alerts|events)$'),q:str=Query('',max_length=200),host:str=Query('',max_length=100),minimum:int=Query(0,ge=0,le=15),status:str=Query('',max_length=30),category:str=Query('',pattern='^(|network)$'),protocol:str=Query('',pattern='^[a-zA-Z0-9_/-]{0,30}$'),record_type:str=Query('',pattern='^[a-z0-9_-]{0,40}$'),review:str=Query('',pattern='^(|Safe|Suspicious|Changed)$'),port:int|None=Query(None,ge=1,le=65535),include_safe:bool=False,maximum:int|None=Query(None,ge=0,le=15),rule_id:str=Query('',pattern='^[0-9]{0,20}$'),source_ip:str=Query('',max_length=60),destination_ip:str=Query('',max_length=60),page:int=Query(0,ge=0,le=199),size:int=Query(50,ge=1,le=50),actor=Depends(user)):
    filters=await queue_filters(start,end,kind,q,host,status,category,protocol,port,include_safe,record_type,review,maximum,rule_id,source_ip,destination_ip)
    body={'size':size,'from':page*size,'query':{'bool':{'filter':filters}},'sort':[{'timestamp':'desc'},{'id':{'order':'desc','unmapped_type':'keyword'}}], 'aggs':{'levels':{'range':{'field':'rule.level','ranges':[{'key':'Critical','from':12},{'key':'High','from':10,'to':12},{'key':'Medium','from':7,'to':10},{'key':'Low','to':7}]}},'hosts':{'terms':{'field':'agent.name','size':50}},'rules':{'terms':{'field':'rule.id','size':8},'aggs':{'example':{'top_hits':{'size':1,'_source':['rule.description']}}}}}}
    if minimum:body['post_filter']={'range':{'rule.level':{'gte':minimum}}}
    suspicious=[scope_query(p) for p in active_policies() if p['classification']=='Suspicious']
    if suspicious and kind=='alerts':
        body['query']['bool']['should']=[{'constant_score':{'filter':{'bool':{'should':suspicious,'minimum_should_match':1}},'boost':100}}]
        body['sort'].insert(0,{'_score':'desc'})
    result=await asyncio.to_thread(indexer.search,kind,body)
    events=attach_state([normalize(h) for h in result.get('hits',{}).get('hits',[])])
    total=result.get('hits',{}).get('total',{}).get('value',0)
    # Queue returns concise facts, investigation endpoint returns full content.
    for e in events:
        e.pop('evidence',None);e.pop('guidance',None);e.pop('observations',None);e.pop('gaps',None)
        e['facts']=[x|{'value':str(x['value'])[:240]} for x in e['facts'][:(6 if e.get('network_context') else 5)]]
    return {'events':events,'total':total,'page':page,'size':size,'has_more':(page+1)*size<min(total,10000),'page_limit':10000,'aggregations':result.get('aggregations',{}),'query_ms':result.get('took'),'queried_at':time.time()}


def policy_aggregations():
    policies=active_policies();safe=[scope_query(p) for p in policies if p['classification']=='Safe'];sus=[scope_query(p) for p in policies if p['classification']=='Suspicious']
    suspicious={'bool':{'should':sus,'minimum_should_match':1}} if sus else {'match_none':{}}
    safe_query={'bool':{'filter':[{'bool':{'should':safe,'minimum_should_match':1}}],'must_not':[suspicious]}} if safe else {'match_none':{}}
    return {'safe':{'filter':safe_query},'suspicious':{'filter':suspicious}}


@app.get('/api/alert-groups')
async def alert_groups(start:str,end:str,q:str=Query('',max_length=200),host:str=Query('',max_length=100),minimum:int=Query(0,ge=0,le=15),status:str=Query('Active',max_length=30),include_safe:bool=False,rule_id:str=Query('',pattern='^[0-9]{0,20}$'),maximum:int|None=Query(None,ge=0,le=15),limit:int=Query(100,ge=1,le=200),protocol:str=Query('',pattern='^[a-zA-Z0-9_/-]{0,30}$'),port:int|None=Query(None,ge=1,le=65535),source_ip:str=Query('',max_length=60),destination_ip:str=Query('',max_length=60),review:str=Query('',pattern='^(|Safe|Suspicious|Changed)$'),actor=Depends(user)):
    filters=await queue_filters(start,end,'alerts',q,host,status,include_safe=include_safe,rule_id=rule_id,maximum=maximum,protocol=protocol,port=port,source_ip=source_ip,destination_ip=destination_ip,review=review)
    if minimum:filters.append({'range':{'rule.level':{'gte':minimum}}})
    body=alert_summary_query(filters,limit);body['aggs']['patterns']['aggs'].update(policy_aggregations())
    result=await asyncio.to_thread(indexer.search,'alerts',body);bucket_data=result.get('aggregations',{}).get('patterns',{});groups=[]
    for bucket in bucket_data.get('buckets',[]):
        hit=bucket['latest']['hits']['hits'][0];event=normalize(hit);rid=str(bucket['key']);criteria={'rule':rid}
        if host:criteria['host']=host
        signatures=bucket['signatures']['buckets'];checks=bucket['checks']['buckets']
        title='Network sensor detections' if len(signatures)>1 else 'Configuration assessment findings' if len(checks)>1 else event['title']
        groups.append({'key':rid,'title':title,'latest_title':event['title'],'rule_id':rid,'level':int(bucket['max_level'].get('value') or 0),'count':bucket['doc_count'],'hosts':bucket['hosts']['buckets'],'other_hosts':bucket['hosts'].get('sum_other_doc_count',0),'objects':bucket['objects']['buckets'],'signatures':signatures,'checks':checks,'other_objects':bucket['objects'].get('sum_other_doc_count',0),'first':bucket['first'].get('value_as_string'),'last':bucket['last'].get('value_as_string'),'criteria':criteria,'suggested_scope':suggested_scope(event,hit['_source']),'kind':'alert-rule','safe_count':bucket['safe']['doc_count'],'suspicious_count':bucket['suspicious']['doc_count'],'sample_ref':event['ref']})
    groups.sort(key=lambda g:(-bool(g['suspicious_count']),-g['count'],-g['level'],g['rule_id']))
    return {'groups':groups,'total':result['hits']['total']['value'],'represented':sum(g['count'] for g in groups),'other_alerts':bucket_data.get('sum_other_doc_count',0),'count_error_upper_bound':bucket_data.get('doc_count_error_upper_bound',0),'partial':bool(bucket_data.get('sum_other_doc_count',0) or bucket_data.get('doc_count_error_upper_bound',0)),'limit':limit,'notice':'One summary per detection rule across the selected window. Host and changed-object breakdowns sit inside the summary; changing hashes and timestamps no longer create cards. Rule counts use index aggregations, not a newest-500-event sample.'}


@app.get('/api/alert-groups/{rid}/activity')
async def alert_activity(rid:str,start:str,end:str,q:str=Query('',max_length=200),host:str=Query('',max_length=100),minimum:int=Query(0,ge=0,le=15),status:str=Query('Active',max_length=30),include_safe:bool=False,maximum:int|None=Query(None,ge=0,le=15),limit:int=Query(300,ge=20,le=1000),protocol:str=Query('',pattern='^[a-zA-Z0-9_/-]{0,30}$'),port:int|None=Query(None,ge=1,le=65535),source_ip:str=Query('',max_length=60),destination_ip:str=Query('',max_length=60),review:str=Query('',pattern='^(|Safe|Suspicious|Changed)$'),actor=Depends(user)):
    if not rid.isdigit():raise ValueError('Invalid rule ID')
    filters=await queue_filters(start,end,'alerts',q,host,status,include_safe=include_safe,maximum=maximum,protocol=protocol,port=port,source_ip=source_ip,destination_ip=destination_ip,review=review);filters.append({'term':{'rule.id':rid}})
    if minimum:filters.append({'range':{'rule.level':{'gte':minimum}}})
    result=await asyncio.to_thread(indexer.search,'alerts',{'size':limit,'query':{'bool':{'filter':filters}},'sort':[{'timestamp':'desc'}],'_source':{'excludes':['full_log','data.win.system.message']}})
    events=attach_state([normalize(h) for h in result['hits']['hits']]);items={}
    for event,hit in zip(events,result['hits']['hits']):
        key,material=recurrence_summary(event,hit['_source'])
        item=items.setdefault(key,{'key':key,'subject':material['object'] or material['image'] or event['subject'],'material':material,'count':0,'hosts':set(),'events':[],'hashes':set(),'decisions':set()})
        item['count']+=1;item['hosts'].add(event['host'])
        for fact in event['facts']:
            if 'hash' in fact['label'].lower():item['hashes'].add(str(fact['value']))
        if hit['_source'].get('syscheck',{}).get('sha256_after'):item['hashes'].add(hit['_source']['syscheck']['sha256_after'])
        if event.get('pattern_decision'):item['decisions'].add(event['pattern_decision']['classification'])
        for field in ('evidence','guidance','observations','gaps'):event.pop(field,None)
        event['facts']=event['facts'][:6]
        if len(item['events'])<10:item['events'].append(event)
    for item in items.values():item['hosts']=sorted(item['hosts']);item['hash_variants']=len(item.pop('hashes'));item['decisions']=sorted(item['decisions'])
    return {'items':sorted(items.values(),key=lambda g:-g['count']),'sampled':len(events),'total':result['hits']['total']['value'],'partial':result['hits']['total']['value']>len(events),'notice':'Activity detail is a bounded sample of this rule. Stable objects/commands/principals group together; changing hashes remain evidence. Parent counts cover the full selected window. Up to ten source events are listed per activity.'}


@app.get('/api/network-patterns')
async def network_patterns(start:str,end:str,q:str=Query('',max_length=200),host:str=Query('',max_length=100),protocol:str=Query('',pattern='^[a-zA-Z0-9_/-]{0,30}$'),port:int|None=Query(None,ge=1,le=65535),source_ip:str=Query('',max_length=60),destination_ip:str=Query('',max_length=60),review:str=Query('',pattern='^(|Safe|Suspicious|Changed)$'),include_safe:bool=False,order:str=Query('records',pattern='^(records|upload|sources)$'),limit:int=Query(40,ge=1,le=100),actor=Depends(user)):
    filters=await queue_filters(start,end,'events',q,host,'','network',protocol,port,review=review,source_ip=source_ip,destination_ip=destination_ip)
    if not include_safe:
        safe=policy_filter(active_policies())
        if safe:filters.append(safe)
    body=traffic_query(filters,limit);body['aggs']['destinations']['aggs'].update(policy_aggregations())
    rank={'records':'_count','upload':'to_server','sources':'source_count'}[order]
    body['aggs']['destinations']['terms']['order']=([{'suspicious':'desc'}] if any(p['classification']=='Suspicious' for p in active_policies()) else [])+[{rank:'desc'}]
    result=await asyncio.to_thread(indexer.search,'events',body);aggregations=result.get('aggregations',{});destinations=aggregations.get('destinations',{});buckets=destinations.get('buckets',[])
    names_result=await asyncio.to_thread(indexer.search,'events',server_names_query([time_filter(start,end)],[b['key'] for b in buckets])) if buckets else {}
    names={b['key']:b for b in names_result.get('aggregations',{}).get('destinations',{}).get('buckets',[])};assets=metadata('assets.json');patterns=[]
    for b in buckets:
        ip=b['key'];context=address_context(ip,assets);n=names.get(ip,{})
        patterns.append({'key':ip,'kind':'network-destination','criteria':{'destination_ip':ip},'destination':context,'records':b['doc_count'],'flow_estimate':int(b['flow_count'].get('value',0)),'sources':[address_context(s['key'],assets)|{'records':s['doc_count']} for s in b['sources']['buckets']],'source_estimate':int(b['source_count'].get('value',0)),'ports':b['ports']['buckets'],'protocols':b['protocols']['buckets'],'collectors':b['collectors']['buckets'],'bytes_to_server':int(b['to_server'].get('value',0)),'bytes_to_client':int(b['to_client'].get('value',0)),'records_with_bytes':b['bytes_records']['doc_count'],'first':b['first'].get('value_as_string'),'last':b['last'].get('value_as_string'),'server_names':list(dict.fromkeys(x['key'] for category in ('sni','http') for x in n.get(category,{}).get('buckets',[]))),'signatures':n.get('signatures',{}).get('buckets',[]),'safe_count':b['safe']['doc_count'],'suspicious_count':b['suspicious']['doc_count'],'sample_ref':{'index':b['sample']['hits']['hits'][0]['_index'],'id':b['sample']['hits']['hits'][0]['_id']}})
    for pattern in patterns:
        pattern['flow_estimate']=min(pattern['records'],pattern['flow_estimate'])
        pattern['source_estimate']=min(pattern['records'],pattern['source_estimate'])
    order_key={'records':'records','upload':'bytes_to_server','sources':'source_estimate'}[order]
    patterns.sort(key=lambda p:(-bool(p['suspicious_count']),-p[order_key]))
    return {'patterns':patterns,'total_flow_records':result['hits']['total']['value'],'other_flow_records':destinations.get('sum_other_doc_count',0),'partial':bool(destinations.get('sum_other_doc_count',0) or destinations.get('doc_count_error_upper_bound',0)),'talkers':[address_context(b['key'],assets)|{'records':b['doc_count'],'destination_estimate':int(b['destinations'].get('value',0)),'port_estimate':int(b['ports'].get('value',0))} for b in aggregations.get('talkers',{}).get('buckets',[])],'notice':'Flow-record totals and reported bytes come from indexed Suricata flow events, not all protocol logs. Flow/source cardinalities are estimates; repeated sensor updates or mirrored copies can inflate bytes and records. Server names/signatures are observations for this IP in the time window, not proof every flow used that domain. Traffic volume and a shared public IP are review signals, not confirmed malicious infrastructure. No external reputation feed is configured.'}


@app.get('/api/dashboard')
async def dashboard(start:str,end:str,actor=Depends(user)):
    window=time_filter(start,end);hours=(datetime.fromisoformat(end.replace('Z','+00:00'))-datetime.fromisoformat(start.replace('Z','+00:00'))).total_seconds()/3600
    interval='1h' if hours<=48 else '3h' if hours<=168 else '12h'
    filters=await queue_filters(start,end,'alerts','','','Active')
    suspicious=[scope_query(p) for p in active_policies() if p['classification']=='Suspicious']
    alerts=await asyncio.to_thread(indexer.search,'alerts',alert_dashboard_query(filters,interval,suspicious))
    raw=await asyncio.to_thread(indexer.search,'events',raw_dashboard_query(window,interval))
    recorded=await asyncio.to_thread(indexer.search,'alerts',{'size':0,'query':window})
    events=attach_state([normalize(h) for h in alerts['hits']['hits']])
    for event in events:
        for field in ('evidence','guidance','observations','gaps'):event.pop(field,None)
        event['facts']=event['facts'][:6]
    inventory=metadata('inventory.json');container=inventory.get('inventory',{})
    agents=container if isinstance(container,list) else container.get('data',[])
    if not isinstance(agents,list):agents=[]
    freshness=raw.get('aggregations',{});hosts=freshness.get('hosts',{}).get('buckets',[])
    cutoff=time.time()-900;stale=[h for h in hosts if (h['latest'].get('value') or 0)/1000<cutoff]
    return {'detection_context':{'recorded_occurrences':recorded['hits']['total']['value'],'visible_occurrences':alerts['hits']['total']['value'],'distinct_patterns_estimate':int(alerts['aggregations']['distinct_patterns']['value']),'pattern_definition':'Rule plus sensor signature or configuration-check identity; cardinality estimate','distinct_rules_estimate':int(alerts['aggregations']['distinct_rules']['value']),'correlated_incidents':None,'incident_note':'Not automatically declared. Run bounded evidence correlation below; candidates require analyst review.','investigations':store.case_counts()},'start':start,'end':end,'interval':interval,'active_alerts':alerts['hits']['total']['value'],'raw_records':raw['hits']['total']['value'],'alerts':alerts['aggregations'],'network':freshness.get('network',{}),'priority_events':events,'latest_raw':freshness.get('latest',{}).get('value_as_string'),'coverage':{'registered':len(agents),'reporting_agents':sum(str(a.get('status','')).lower()=='active' for a in agents),'nonreporting':[{'name':a['name'],'status':a.get('status','Unknown')} for a in agents if str(a.get('status','')).lower()!='active'],'stale_sources':[{'name':h['key'],'latest':h['latest'].get('value_as_string')} for h in stale]},'policies':{'safe':sum(p['classification']=='Safe' for p in active_policies()),'suspicious':sum(p['classification']=='Suspicious' for p in active_policies())},'notice':'Priority combines analyst-marked suspicious matches with original detection severity. Alerts, traffic concentration and source gaps are review leads; this overview does not claim confirmed compromise.'}


async def source_event(index,eid):
    try:hit=await asyncio.to_thread(indexer.get,index,eid)
    except LookupError:raise HTTPException(404,'The source event is unavailable. It may have expired from retention. Check a pinned case copy if one exists.')
    return hit,normalize(hit)


def rule_chain(rid):
    catalogue=metadata('catalogue.json');rules=catalogue.get('rules',{});chain=[];seen=set()
    def visit(key,depth=0):
        if key in seen or depth>8:return
        seen.add(key)
        rule=rules.get(key)
        if not rule:return
        chain.append(rule)
        for parent in rule.get('parents',[]):visit(parent,depth+1)
    visit(rid)
    return {'rules':chain,'catalogue_updated':catalogue.get('updated'),'notice':'These are the currently installed rule definitions. They may differ from the definition at the historical event time. Wazuh reported the match; this console does not re-run its regex or correlation engine.','missing':not bool(chain)}


@app.get('/api/alert')
async def alert(index:str,eid:str=Query(max_length=512),actor=Depends(user)):
    hit,event=await source_event(index,eid)
    attach_state([event])
    rules=rule_chain(event['rule_id'])
    event,rules=focus_evidence(event,hit['_source'],rules)
    return {'event':event,'rules':rules,'decoded':decoded_literals(event),'annotations':store.annotations(event['key']),'raw':hit['_source']}


def context_terms(event,include_addresses=True):
    identity=event['identity'];host={'term':{'agent.name':event['host']}}
    matches=[]
    for field,key in [('data.win.eventdata.processGuid','process_guid'),('data.win.eventdata.parentProcessGuid','process_guid'),('data.win.eventdata.processGuid','parent_guid'),('data.win.eventdata.scriptBlockId','script_block_id'),('data.audit.id','audit_id')]:
        value=identity.get(key)
        if value:
            original=identity.get(key+'_raw') or ('{'+value+'}' if key.endswith('guid') else value)
            matches.append({'bool':{'filter':[host,{'terms':{field:list(dict.fromkeys([value,original,original.upper(),original.lower()]))}}]}})
    if identity.get('community_id'):matches.append({'term':{'data.community_id':identity['community_id']}})
    if identity.get('flow_id'):matches.append({'bool':{'filter':[host,{'term':{'data.flow_id':identity['flow_id']}}]}})
    if identity.get('logon_id') and identity['logon_id'] not in ('0x0','0x3e7','0x3e4','0x3e5'):
        for field in ('data.win.eventdata.targetLogonId','data.win.eventdata.subjectLogonId','data.win.eventdata.logonId'):
            matches.append({'bool':{'filter':[host,{'term':{field:identity['logon_id']}}]}})
    if not include_addresses:return matches
    ips={identity.get('source_ip'),identity.get('destination_ip'),event.get('agent_ip')}-{None,'','127.0.0.1','::1','0.0.0.0'}
    for field in ['data.src_ip','data.dest_ip','data.srcip','data.dstip','data.win.eventdata.sourceIp','data.win.eventdata.destinationIp','data.win.eventdata.ipAddress','agent.ip']:
        if ips:matches.append({'terms':{field:list(ips)}})
    return matches or [host]


@app.get('/api/investigation')
async def investigation(index:str,eid:str=Query(max_length=512),minutes:int=Query(5,ge=1,le=60),actor=Depends(user)):
    key=(index,eid,minutes)
    if key in cache and time.time()-cache[key][0]<20:return cache[key][1]
    hit,seed=await source_event(index,eid)
    stamp=datetime.fromtimestamp(epoch(seed['time']),timezone.utc)
    start=(stamp-timedelta(minutes=minutes)).isoformat();end=(stamp+timedelta(minutes=minutes)).isoformat()
    window=time_filter(start,end)
    base={'size':200,'sort':[{'timestamp':'asc'}]}
    identified={'bool':{'filter':[window], 'should':context_terms(seed),'minimum_should_match':1}}
    host_context={'bool':{'filter':[window,{'term':{'agent.name':seed['host']}}]}}
    # Serial queries bound the load on the existing indexer.
    direct=await asyncio.to_thread(indexer.search,'events',base|{'query':identified})
    terms=context_terms(seed,include_addresses=False)
    exact=await asyncio.to_thread(indexer.search,'events',base|{'size':150,'query':{'bool':{'filter':[window],'should':terms,'minimum_should_match':1}}}) if terms else {'hits':{'hits':[],'total':{'value':0}}}
    nearby=await asyncio.to_thread(indexer.search,'events',base|{'size':150,'query':host_context})
    alert_result=await asyncio.to_thread(indexer.search,'alerts',{'size':100,'query':identified,'sort':[{'timestamp':'asc'}]})
    events={}
    for h in direct['hits']['hits']+nearby['hits']['hits']+exact['hits']['hits']+[hit]:
        e=normalize(h)
        # Prefer native alert provenance for the seed; otherwise retain archive refs.
        if e['key'] not in events or e['ref']==seed['ref']:events[e['key']]=e
    ordered=sorted(events.values(),key=lambda e:epoch(e['time']))
    # Follow identifiers outwards from the seed, including child activity and
    # destination sessions. Broad IP/time matches remain context only.
    searched_links=set();expansion_partial=False;expansion_queries=0
    for depth in range(3):
        connected=evidence_links(ordered,seed);linked=[e for e in ordered if e['key'] in connected['linked_keys']]
        clauses=[]
        for e in linked:
            identity=e['identity'];host_clause={'term':{'agent.name':e['host']}}
            guid=identity.get('process_guid')
            if guid and (e['host'],guid) not in searched_links:
                searched_links.add((e['host'],guid));values=[guid,'{'+guid+'}','{'+guid.upper()+'}']
                for field in ('data.win.eventdata.processGuid','data.win.eventdata.parentProcessGuid'):
                    clauses.append({'bool':{'filter':[host_clause,{'terms':{field:values}}]}})
            session=identity.get('logon_id','').lower()
            if session and session not in ('0x0','0x3e7','0x3e4','0x3e5') and (e['host'],'session:'+session) not in searched_links:
                searched_links.add((e['host'],'session:'+session))
                for field in ('data.win.eventdata.logonId','data.win.eventdata.targetLogonId','data.win.eventdata.subjectLogonId'):
                    clauses.append({'bool':{'filter':[host_clause,{'term':{field:identity['logon_id']}}]}})
            flow=tuple_key(e)
            if flow and ('flow',flow) not in searched_links:
                searched_links.add(('flow',flow))
                for reverse in (False,True):
                    keys=('destination_ip','destination_port','source_ip','source_port','protocol') if reverse else ('source_ip','source_port','destination_ip','destination_port','protocol')
                    # Native sensor tuples are exact; the graph subsequently
                    # checks recorded event/flow time before connecting them.
                    fields=('data.src_ip','data.src_port','data.dest_ip','data.dest_port','data.proto')
                    clauses.append({'bool':{'filter':[{'term':{f:identity[k].upper() if k=='protocol' else identity[k]}} for f,k in zip(fields,keys)]}})
                if e['family']=='Network connection' and identity['protocol']=='tcp' and identity['destination_port'] in ('445','135','5985','5986','3389'):
                    clauses.append({'bool':{'filter':[{'term':{'agent.ip':identity['destination_ip']}},{'term':{'data.win.system.eventID':'4624'}},{'term':{'data.win.eventdata.ipAddress':identity['source_ip']}},{'term':{'data.win.eventdata.ipPort':identity['source_port']}}]}})
        if not clauses:break
        if len(clauses)>80:expansion_partial=True
        expanded=await asyncio.to_thread(indexer.search,'events',{'size':180,'sort':[{'timestamp':'asc'}],'query':{'bool':{'filter':[window],'should':clauses[:80],'minimum_should_match':1}}})
        expansion_queries+=1;expansion_partial |= expanded['hits']['total']['value']>180
        before=len(events)
        for h in expanded['hits']['hits']:
            e=normalize(h)
            if e['key'] not in events and len(events)<650:events[e['key']]=e
        ordered=sorted(events.values(),key=lambda e:epoch(e['time']))
        if len(events)==before:break
        if depth==2:expansion_partial=True
    for e in ordered:e['relation']=relation(seed,e)
    related=attach_state([normalize(h) for h in alert_result['hits']['hits']])
    for e in related:e['relation']=relation(seed,e)
    graph=process_graph(ordered)
    ancestors=[];searched=set()
    for depth in range(3):
        missing=[n for n in graph['nodes'] if not n['observed'] and n['host']==seed['host'] and n['guid'] not in searched][:12]
        if not missing:break
        guids=[]
        for n in missing:
            searched.add(n['guid']);g=n['guid'];guids.extend([g,'{'+g+'}','{'+g.upper()+'}'])
        for e in ordered+ancestors:
            if e['identity'].get('parent_guid') in searched and e['identity'].get('parent_guid_raw'):guids.append(e['identity']['parent_guid_raw'])
        parent_result=await asyncio.to_thread(indexer.search,'events',{'size':40,'query':{'bool':{'filter':[{'term':{'agent.name':seed['host']}},{'term':{'data.win.system.eventID':'1'}},{'terms':{'data.win.eventdata.processGuid':list(set(guids))}},{'range':{'timestamp':{'gte':(stamp-timedelta(days=3)).isoformat(),'lte':end}}}]}}})
        found=[normalize(h) for h in parent_result['hits']['hits']]
        known={e['key'] for e in ordered+ancestors}
        added=[e for e in found if e['key'] not in known]
        if not added:break
        for e in added:e['relation']={'basis':'Retained process-creation context; recorded GUID','strength':'identifier'}
        ancestors+=added;graph=process_graph(ordered+ancestors)
    graph['notice']+=' Up to three ancestor lookups can include creation events from the retained three-day archive, outside the selected timeline window.'
    result={'seed':seed['ref'],'start':start,'end':end,'minutes':minutes,'events':ordered,'process_context':ancestors,'related_alerts':related,'graph':graph,'script':script_fragments(seed,ordered),'counts':{'matching_events':direct['hits']['total']['value'],'identifier_events':exact['hits']['total']['value'],'host_context_events':nearby['hits']['total']['value'],'related_alerts':alert_result['hits']['total']['value'],'loaded':len(ordered)},'truncated':direct['hits']['total']['value']>200 or exact['hits']['total']['value']>150 or nearby['hits']['total']['value']>150 or alert_result['hits']['total']['value']>100,'notice':'Identifier and flow associations are labeled separately from time/address context. Contextual proximity does not establish causation. Results are bounded; use the event explorer to paginate or narrow a busy window.'}
    result['sequence']=evidence_sequence(seed,ordered,result['truncated'])
    result['truncated'] |= expansion_partial
    result['correlation']=evidence_links(ordered+ancestors,seed,result['truncated'])
    result['truncated'] |= result['correlation']['partial']
    result['correlation']['expansion_queries']=expansion_queries
    # Keep payloads bounded while preserving all evidence on demand via /api/alert.
    for e in ordered+related+ancestors:
        e.pop('evidence',None);e.pop('guidance',None);e.pop('observations',None);e.pop('gaps',None)
        e['facts']=[x|{'value':str(x['value'])[:500]} for x in e['facts'][:5]]
    cache[key]=(time.time(),result)
    for k in list(cache):
        if not isinstance(k,str) and (len(cache)>24 or time.time()-cache[k][0]>120):cache.pop(k,None)
    return result


@app.get('/api/correlations')
async def correlations(start:str,end:str,actor=Depends(user)):
    """On-demand bounded review, never a claim to enumerate all incidents."""
    filters=await queue_filters(start,end,'alerts','','','Active')
    filters.append({'exists':{'field':'data.win.eventdata.processGuid'}})
    result=await asyncio.to_thread(indexer.search,'alerts',{'size':80,'query':{'bool':{'filter':filters}},'sort':[{'rule.level':'desc'},{'timestamp':'desc'}]})
    seeds=[];seen=set()
    for hit in result['hits']['hits']:
        event=normalize(hit);key=(event['host'],event['identity'].get('process_guid'))
        if key in seen:continue
        seen.add(key);seeds.append(event)
        if len(seeds)==4:break
    candidates=[];used=set()
    for seed in seeds:
        context=await investigation(seed['ref']['index'],seed['ref']['id'],5,actor)
        component=context['correlation']['selected']
        if not component or not component['candidate']:continue
        identities={e['host']+'|'+e['identity']['process_guid'] for e in context['events']+context.get('process_context',[]) if e['key'] in component['event_keys'] and e['identity'].get('process_guid')}
        if identities & used:continue
        used.update(identities)
        candidates.append(component|{'seed':seed['ref'],'title':seed['title'],'subject':seed['subject'],'partial':context['truncated'],'source_window':{'start':context['start'],'end':context['end']}})
    return {'candidates':candidates,'seeds_reviewed':len(seeds),'matching_seed_occurrences':result['hits']['total']['value'],'partial':True,'notice':'On-demand sample of up to four distinct process seeds, ordered by original severity and recency, with ±5 minute context. Overlapping process identities are deduplicated. These evidence-linked candidates are not confirmed incidents or an exhaustive incident count. Open a candidate to inspect each relationship and preserve it as an analyst investigation.'}


class Ref(BaseModel):
    index:str=Field(max_length=200)
    eid:str=Field(min_length=1,max_length=512)


class SequenceRef(Ref):
    minutes:int=Field(default=5,ge=1,le=60)
    case_id:str=Field(default='',max_length=100)
    title:str=Field(default='',max_length=200)


@app.post('/api/correlations/preserve')
async def preserve_correlation(body:SequenceRef,actor=Depends(analyst)):
    context=await investigation(body.index,body.eid,body.minutes,actor)
    component=context['correlation']['selected']
    if not component:raise ValueError('No evidence-linked component is available for this seed')
    events=[e for e in context['events']+context.get('process_context',[]) if e['key'] in component['event_keys']]
    if len(events)>60:raise ValueError('Narrow the context window to preserve at most 60 linked source records')
    refs=[{'index':e['ref']['index'],'eid':e['ref']['id']} for e in events]
    hits=await asyncio.to_thread(indexer.get_many,refs)
    entries=[(normalize(h),h['_source']) for h in hits]
    if any(e['key']!=old['key'] for (e,source),old in zip(entries,events)):raise StateConflict('A source identity changed; reload the sequence')
    analysis={'correlation':component,'partial':context['truncated'],'normalizer_version':VERSION,'window':{'start':context['start'],'end':context['end']}}
    store.validate_sequence(entries,analysis)
    cid=body.case_id or store.save_case(None,body.title or 'Evidence-linked sequence',context['correlation']['notice'],'Investigating',actor['name'],actor['name'])
    added=store.pin_sequence(cid,entries,analysis,actor['name'])
    return {'case_id':cid,'preserved':added,'partial':context['truncated']}


class Disposition(Ref):
    status:str=Field(max_length=30)
    assignee:str=Field(default='',max_length=80)


class ClearRef(Ref):
    expected_status:str=Field(max_length=30)
    expected_updated:float|None=None


class ClearBody(BaseModel):
    items:list[ClearRef]=Field(min_length=1,max_length=50)


class PatternPolicy(BaseModel):
    kind:str=Field(max_length=40)
    criteria:dict[str,str]
    classification:str=Field(max_length=20)
    rationale:str=Field(min_length=10,max_length=2000)


@app.get('/api/pattern-policies')
def pattern_policies(actor=Depends(user)):
    return {'policies':[p|{'history':store.annotations('pattern:'+p['id'])['history']} for p in store.pattern_policies(include_disabled=True)],'notice':'Safe scopes require bounded evidence conditions. Changed conditions remain visible and carry a changed-scope badge; original evidence remains searchable with Include safe enabled. Suspicious wins over Safe when scopes overlap. Policies apply when records are queried, including future matching records; they do not change Wazuh detection rules.'}


@app.post('/api/pattern-policies')
async def save_pattern_policy(body:PatternPolicy,actor=Depends(analyst)):
    if body.classification=='Safe':
        criteria=validate_safe(body.kind,body.criteria)
        check=await asyncio.to_thread(indexer.search,'alerts' if body.kind=='alert-rule' else 'events',{'size':1,'query':scope_query({'criteria':criteria})})
        if not check['hits']['total']['value']:raise ValueError('Safe criteria must match retained evidence; inspect a source and use its exact recorded fields')
    key=store.save_pattern_policy(body.kind,body.criteria,body.classification,body.rationale,actor['name'])
    cache.pop('pattern-policy-cache',None)
    for cache_key in list(cache):
        if not isinstance(cache_key,str):cache.pop(cache_key,None)
    return {'id':key,'policies':active_policies()}


@app.delete('/api/pattern-policies/{key}')
def disable_pattern_policy(key:str,actor=Depends(analyst)):
    if not re.fullmatch(r'[a-f0-9]{64}',key):raise ValueError('Invalid pattern policy')
    store.disable_pattern_policy(key,actor['name']);cache.pop('pattern-policy-cache',None)
    for cache_key in list(cache):
        if not isinstance(cache_key,str):cache.pop(cache_key,None)
    return {'policies':active_policies()}


class GroupDecision(Ref):
    classification:str=Field(max_length=40)
    rationale:str=Field(min_length=10,max_length=2000)


@app.put('/api/alert-groups/decision')
async def group_decision(body:GroupDecision,actor=Depends(analyst)):
    if not body.index.startswith('wazuh-alerts-'):raise ValueError('Assess recurring patterns from native alerts')
    hit,event=await source_event(body.index,body.eid);key,material=grouping_signature(event,hit['_source'])
    store.classify_group(key,body.classification,body.rationale,actor['name'])
    return {'key':key,'decision':store.group_decisions().get(key)}


@app.post('/api/alerts/clear')
async def clear_alerts(body:ClearBody,actor=Depends(analyst)):
    refs=[item.model_dump() for item in body.items]
    if any(not item['index'].startswith('wazuh-alerts-') for item in refs):raise ValueError('Only native detection alerts can be cleared')
    if len({(r['index'],r['eid']) for r in refs})!=len(refs):raise ValueError('Select each alert only once')
    try:hits=await asyncio.to_thread(indexer.get_many,refs)
    except LookupError as e:raise HTTPException(404,str(e))
    entries=[ref|{'key':normalize(hit)['key']} for ref,hit in zip(refs,hits)]
    return store.clear_alerts(entries,actor['name'])


@app.post('/api/alerts/clear/{batch}/undo')
def undo_clear(batch:str,actor=Depends(analyst)):
    if not re.fullmatch('[a-f0-9]{32}',batch):raise ValueError('Invalid clear action')
    return store.undo_clear(batch,actor['name'],admin=actor['role']=='admin')


@app.put('/api/disposition')
async def disposition(body:Disposition,actor=Depends(analyst)):
    hit,event=await source_event(body.index,body.eid)
    if not body.index.startswith('wazuh-alerts-'):raise ValueError('Change the disposition from the native alert queue. Archive records retain their original classification metadata.')
    with store.db() as db:
        db.execute('CREATE TABLE IF NOT EXISTS event_refs(key TEXT PRIMARY KEY,source_index TEXT NOT NULL,source_id TEXT NOT NULL)')
        db.execute('INSERT OR REPLACE INTO event_refs VALUES(?,?,?)',(event['key'],body.index,body.eid))
    store.state(event['key'],body.status,body.assignee,actor['name'])
    return store.states([event['key']])[event['key']]


class Note(BaseModel):
    subject:str=Field(min_length=1,max_length=100)
    body:str=Field(min_length=1,max_length=20000)


@app.post('/api/notes')
def note(body:Note,actor=Depends(analyst)):
    if not re.fullmatch(r'(?:[a-f0-9]{64}|case-[a-f0-9]{16})',body.subject):raise ValueError('Invalid investigation reference')
    store.note(body.subject,body.body,actor['name']);return store.annotations(body.subject)


class CaseBody(BaseModel):
    id:str|None=Field(default=None,max_length=30)
    title:str=Field(min_length=1,max_length=200)
    description:str=Field(default='',max_length=20000)
    status:str=Field(default='New',max_length=30)
    assignee:str=Field(default='',max_length=80)


@app.get('/api/cases')
def cases(actor=Depends(user)):return {'cases':store.cases()}


@app.post('/api/cases')
def create_case(body:CaseBody,actor=Depends(analyst)):
    if body.id and not store.case(body.id):raise HTTPException(404,'Case not found')
    cid=store.save_case(body.id,body.title,body.description,body.status,body.assignee,actor['name'])
    return store.case(cid)


@app.get('/api/cases/{cid}')
def case(cid:str,actor=Depends(user)):
    result=store.case(cid)
    if not result:raise HTTPException(404,'Case not found')
    return result


@app.post('/api/cases/{cid}/evidence')
async def pin(cid:str,body:Ref,actor=Depends(analyst)):
    hit,event=await source_event(body.index,body.eid)
    event,rules=focus_evidence(event,hit['_source'],rule_chain(event['rule_id']))
    store.pin(cid,event,hit['_source'],actor['name'],{'rules':rules,'decoded':decoded_literals(event),'normalizer_version':VERSION});return store.case(cid)


@app.get('/api/cases/{cid}/export')
def export_case(cid:str,actor=Depends(user)):
    result=store.case(cid)
    if not result:raise HTTPException(404,'Case not found')
    result['exported_at']=time.time();result['exported_by']=actor['name'];result['normalizer_version']=VERSION
    return JSONResponse(result,headers={'Content-Disposition':f'attachment; filename="{cid}.json"'})


@app.get('/api/catalogue')
def catalogue(q:str=Query('',max_length=200),page:int=Query(0,ge=0,le=2000),actor=Depends(user)):
    data=metadata('catalogue.json');rules=list(data.get('rules',{}).values())
    if q:rules=[r for r in rules if q.lower() in json.dumps(r,ensure_ascii=False).lower()]
    return {'total':len(rules),'rules':rules[page*30:(page+1)*30],'updated':data.get('updated'),'parse_errors':data.get('errors',[])}


@app.get('/api/coverage')
async def coverage(actor=Depends(user)):
    key='coverage-cache'
    if key in cache and time.time()-cache[key][0]<30:return cache[key][1]
    results={}
    for kind in ('alerts','events'):
        results[kind]=await asyncio.to_thread(indexer.search,kind,{'size':0,'aggs':{'latest':{'max':{'field':'timestamp'}},'earliest':{'min':{'field':'timestamp'}},'hosts':{'terms':{'field':'agent.name','size':100},'aggs':{'latest':{'max':{'field':'timestamp'}}}}}})
    data={'version':VERSION,'inventory':metadata('inventory.json'),'catalogue':{'updated':metadata('catalogue.json').get('updated'),'rules':len(metadata('catalogue.json').get('rules',{})),'errors':metadata('catalogue.json').get('errors',[])},'sources':{k:{'total':v['hits']['total']['value'],'aggregations':v['aggregations']} for k,v in results.items()},'limits':{'default_context_minutes':5,'max_context_minutes':60,'max_context_events':500,'query_concurrency':3,'indexer_timeout_seconds':7,'raw_retention_days':CONFIG.get('raw_retention_days'),'alert_retention_days':CONFIG.get('alert_retention_days')},'notice':'Retention windows are configured policy targets, not proof of uninterrupted collection. Earliest/latest indexed timestamps and host freshness show the evidence currently available. Coverage of a specific action must be tested.'}
    since=(datetime.now(timezone.utc)-timedelta(hours=24)).isoformat()
    observations=await asyncio.to_thread(indexer.search,'events',observation_query(since))
    data['telemetry_observations']={'start':since,'rows':observation_rows(data['inventory'],observations,results['alerts']),'notice':'Registration, manager connection state, raw source observations and triggered detections are separate checks. This is a 24-hour observation checklist, not proof that an unobserved source is disabled or that every required action was collected. A controlled expected-action test is needed to establish detection coverage.'}
    cache[key]=(time.time(),data);return data


@app.get('/api/topology')
async def topology(actor=Depends(user)):
    manifest_path=pathlib.Path(CONFIG.get('topology_file','/etc/redsec-soc-console/topology.json'))
    manifest=json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    snapshots={name:metadata(name) for name in {s.get('observation','services.json') for s in manifest.get('services',[])} if re.fullmatch(r'[a-zA-Z0-9_-]+\.json',name)}
    data=build_topology(manifest,snapshots)
    traffic=await asyncio.to_thread(indexer.search,'events',{'size':0,'query':{'exists':{'field':'data.event_type'}},'aggs':{'types':{'terms':{'field':'data.event_type','size':25}},'sensors':{'terms':{'field':'agent.name','size':50}}}})
    return data|{'coverage':await coverage(actor),'soc_observed':metadata('services.json').get('updated'),'ndr_traffic':traffic.get('aggregations',{}).get('types',{}).get('buckets',[]),'sensors':traffic.get('aggregations',{}).get('sensors',{}).get('buckets',[]),'console_reads':['Native Wazuh alerts and indexed raw archives','Installed rule definitions, agent inventory and local service metadata'],'console_writes':['Its own SQLite investigation state','Explicitly pinned evidence snapshots; source records remain read-only'],'outside_console':['Velociraptor forensic collection contents and hunt results','Full packet captures unless collected by another tool','Native Wazuh administration and independent plugin case state']}


class Validation(BaseModel):
    title:str=Field(min_length=1,max_length=200)
    host:str=Field(default='',max_length=100)
    start:str=Field(max_length=50)
    end:str=Field(max_length=50)
    marker:str=Field(min_length=1,max_length=200)


async def check_validation(body):
    filters=[time_filter(body.start,body.end,max_days=3),await search_text(body.marker)]
    if body.host:filters.append({'term':{'agent.name':body.host}})
    result={}
    for kind in ('alerts','events'):
        d=await asyncio.to_thread(indexer.search,kind,{'size':10,'query':{'bool':{'filter':filters}},'sort':[{'timestamp':'asc'}]})
        result[kind]={'count':d['hits']['total']['value'],'examples':[normalize(h) for h in d['hits']['hits']]}
    state='Alerted' if result['alerts']['count'] else 'Observed without an alert' if result['events']['count'] else 'Not observed'
    return {'result':state,'sources':result,'notice':'This result applies only to the exact search, host and indexed time window. No match is not proof the action did not occur. A host filter may exclude network-sensor records collected under a different host name; leave it blank to search across sources.'}


@app.post('/api/validation/check')
async def validation_check(body:Validation,actor=Depends(analyst)):return await check_validation(body)


@app.post('/api/validation')
async def validation_save(body:Validation,actor=Depends(analyst)):
    result=await check_validation(body);vid=secrets.token_hex(12)
    with store.db() as db:
        db.execute('INSERT INTO validations VALUES(?,?,?,?,?,?,?,?)',(vid,body.title,body.host,body.start,body.end,body.marker,time.time(),actor['name']))
        store.record(db,'validation:'+vid,'Validation recorded',{'test':body.model_dump(),'result':result['result'],'counts':{k:v['count'] for k,v in result['sources'].items()}},actor['name'])
    return result|{'id':vid}


@app.get('/api/validation')
def validation_list(actor=Depends(user)):
    with store.db() as db:
        rows=[dict(r) for r in db.execute('SELECT * FROM validations ORDER BY created DESC LIMIT 200')]
        for r in rows:
            hist=db.execute('SELECT detail FROM history WHERE subject=? ORDER BY id DESC LIMIT 1',('validation:'+r['id'],)).fetchone()
            r['last_result']=json.loads(hist[0]) if hist else None
    return {'tests':rows}


class UserBody(BaseModel):
    name:str=Field(min_length=1,max_length=80,pattern=r'^[a-zA-Z0-9_.@-]+$')
    password:str=Field(default='',max_length=512)
    role:str=Field(max_length=20)
    disabled:bool=False


@app.get('/api/users')
def users(actor=Depends(user)):
    rows=store.users()
    return {'users':rows if actor['role']=='admin' else [{'name':r['name']} for r in rows if not r['disabled']]}


@app.put('/api/users')
def save_user(body:UserBody,actor=Depends(admin)):
    if body.password and len(body.password)<12:raise ValueError('Use at least 12 characters')
    store.save_user(body.name,body.password,body.role,body.disabled,actor['name']);return {'users':store.users()}


@app.get('/api/audit')
def audit(actor=Depends(admin)):
    with store.db() as db:return {'history':[dict(r) for r in db.execute('SELECT * FROM history ORDER BY id DESC LIMIT 500')]}


if (FRONT/'assets').exists():app.mount('/assets',StaticFiles(directory=FRONT/'assets'),name='assets')


@app.get('/theme.js')
def theme_bootstrap():return FileResponse(FRONT/'theme.js',media_type='text/javascript',headers={'Cache-Control':'no-cache'})


@app.get('/favicon.svg')
@app.get('/favicon.ico')
def favicon():return FileResponse(FRONT/'favicon.svg',media_type='image/svg+xml')


@app.get('/{path:path}')
def frontend(path:str):
    if path.startswith('api/'):raise HTTPException(404,'Endpoint not found')
    if not (FRONT/'index.html').exists():raise HTTPException(503,'The frontend build is unavailable')
    return FileResponse(FRONT/'index.html',headers={'Cache-Control':'no-cache'})
