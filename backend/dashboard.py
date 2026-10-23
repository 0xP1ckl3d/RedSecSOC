"""Small aggregate queries for a navigable SOC overview."""
def alert_dashboard_query(filters,interval,suspicious):
    query={'bool':{'filter':filters}}
    if suspicious:query['bool']['should']=[{'constant_score':{'filter':{'bool':{'should':suspicious,'minimum_should_match':1}},'boost':100}}]
    return {'size':8,'query':query,'sort':([{'_score':'desc'}] if suspicious else [])+[{'rule.level':'desc'},{'timestamp':'desc'}],'_source':{'excludes':['full_log','data.win.system.message']},'aggs':{
      'distinct_rules':{'cardinality':{'field':'rule.id','precision_threshold':40000}},
      'distinct_patterns':{'cardinality':{'precision_threshold':40000,'script':{'lang':'painless','source':"String r=doc.containsKey('rule.id') && doc['rule.id'].size()>0 ? doc['rule.id'].value.toString() : ''; String suffix=''; for (def f : ['data.alert.signature_id','data.alert.signature','data.sca.check.id','data.sca.check.title']) {if (doc.containsKey(f) && doc[f].size()>0) {suffix=f+':'+doc[f].value.toString(); break;}} return r+'|'+suffix;"}}},
      'levels':{'range':{'field':'rule.level','ranges':[{'key':'Low','to':7},{'key':'Medium','from':7,'to':10},{'key':'High','from':10,'to':12},{'key':'Critical','from':12}]}},
      'hosts':{'terms':{'field':'agent.name','size':10},'aggs':{'level':{'max':{'field':'rule.level'}}}},
      'rules':{'terms':{'field':'rule.id','size':6},'aggs':{'sample':{'top_hits':{'size':1,'_source':['rule.description']}}}},
      'timeline':{'date_histogram':{'field':'timestamp','fixed_interval':interval,'min_doc_count':0}},
      'suspicious':{'filter':{'bool':{'should':suspicious,'minimum_should_match':1}} if suspicious else {'match_none':{}}}
    }}

def raw_dashboard_query(window,interval):
    return {'size':0,'query':window,'aggs':{
      'latest':{'max':{'field':'timestamp'}},'hosts':{'terms':{'field':'agent.name','size':100},'aggs':{'latest':{'max':{'field':'timestamp'}}}},
      'network':{'filter':{'exists':{'field':'data.event_type'}},'aggs':{'types':{'terms':{'field':'data.event_type','size':30}},'timeline':{'date_histogram':{'field':'timestamp','fixed_interval':interval,'min_doc_count':0}}}}
    }}
