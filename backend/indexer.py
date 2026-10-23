import base64
import json
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from search import SEARCH_FIELDS


class IndexerError(Exception):pass


class Indexer:
    def __init__(self,config):
        self.url=config['indexer_url'].rstrip('/')
        self.context=ssl.create_default_context(cafile=config['indexer_ca'])
        self.auth='Basic '+base64.b64encode((config['indexer_user']+':'+config['indexer_password']).encode()).decode()
        self.gate=threading.BoundedSemaphore(3)
        self.last_ok=0
        self.last_error=None
        self.search_field_cache=None

    def request(self,path,body=None,method='POST'):
        if not self.gate.acquire(timeout=2):raise IndexerError('Investigation query capacity is busy. Retry shortly.')
        try:
            req=urllib.request.Request(self.url+path,data=None if body is None else json.dumps(body).encode(),method=method,headers={'Content-Type':'application/json','Authorization':self.auth})
            with urllib.request.urlopen(req,context=self.context,timeout=10) as r:
                content=r.read(16000001)
                if len(content)>16000000:raise IndexerError('Query response exceeded the 16 MB limit. Narrow the time window.')
                result=json.loads(content)
            if result.get('timed_out') or result.get('_shards',{}).get('failed',0):raise IndexerError('The indexer returned incomplete results. Narrow the query and retry.')
            self.last_ok=time.time();self.last_error=None
            return result
        except urllib.error.HTTPError as e:
            if e.code==404:raise LookupError('Source event not found') from e
            self.last_error='HTTP '+str(e.code)
            raise IndexerError('The telemetry service rejected the query. Check service permissions or query parameters.') from e
        except (urllib.error.URLError,ValueError,TimeoutError) as e:
            self.last_error=type(e).__name__
            raise IndexerError('The telemetry query failed or timed out. The source index may be unavailable.') from e
        finally:self.gate.release()

    def valid_index(self,index):
        if not re.fullmatch(r'wazuh-(?:alerts|archives)-[a-zA-Z0-9_.-]+',index):raise ValueError('Invalid source index')
        return urllib.parse.quote(index,safe='-_.')

    def get(self,index,eid):
        return self.request('/'+self.valid_index(index)+'/_doc/'+urllib.parse.quote(eid,safe=''),method='GET')

    def get_many(self,refs):
        for ref in refs:self.valid_index(ref['index'])
        result=self.request('/_mget',{'docs':[{'_index':r['index'],'_id':r['eid']} for r in refs]})
        if len(result.get('docs',[]))!=len(refs) or any(not h.get('found') or h.get('error') for h in result.get('docs',[])):raise LookupError('One or more selected alerts are no longer available. Refresh the inbox.')
        return result['docs']

    def search(self,kind,body):
        indices={'alerts':'wazuh-alerts-*','events':'wazuh-archives-*'}[kind]
        return self.request('/'+indices+'/_search?allow_no_indices=true&ignore_unavailable=true',body|{'timeout':'7s','track_total_hits':True})

    def search_fields(self):
        if self.search_field_cache and time.time()-self.search_field_cache[0]<600:return self.search_field_cache[1]
        requested=','.join(SEARCH_FIELDS)
        result=self.request('/wazuh-alerts-*,wazuh-archives-*/_field_caps?fields='+urllib.parse.quote(requested,safe=',.*')+'&allow_no_indices=true&ignore_unavailable=true',method='GET')
        fields=[field for field,types in result.get('fields',{}).items() if any(t in ('keyword','text') and info.get('searchable') for t,info in types.items())]
        self.search_field_cache=(time.time(),fields);return fields
