import json,pathlib,sys,tempfile,unittest,copy
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'backend'))
from patterns import validate_criteria,decision_for,policy_filter,scope_query,recurrence_summary,alert_summary_query,traffic_query
from engine import normalize
from store import Store

def integrity_event(checksum,host='EXAMPLE',path='/etc/example/status'):
 s={'timestamp':'2026-10-23T00:00:00Z','agent':{'name':host},'rule':{'id':'550','level':7,'description':'Integrity checksum changed.'},'syscheck':{'path':path,'event':'modified','sha256_after':checksum,'mtime_after':'variable'}}
 return normalize({'_index':'wazuh-alerts-test','_id':checksum,'_source':s}),s

class PatternTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.store=Store(str(pathlib.Path(self.temp.name)/'state.db'))
 def tearDown(self):self.temp.cleanup()
 def test_changed_hashes_do_not_split_stable_activity(self):
  a,s=integrity_event('first');b,t=integrity_event('second')
  self.assertEqual(recurrence_summary(a,s)[0],recurrence_summary(b,t)[0])
  c,u=integrity_event('third',path='/etc/example/other')
  self.assertNotEqual(recurrence_summary(a,s)[0],recurrence_summary(c,u)[0])
 def test_parent_counts_use_index_aggregation_and_rule_id_not_hash(self):
  q=alert_summary_query([{'match_all':{}}]);self.assertEqual(q['size'],0);self.assertEqual(q['aggs']['patterns']['terms']['field'],'rule.id')
  self.assertNotIn('sha256',json.dumps(q))
 def test_safe_integrity_scope_survives_time_but_reopens_changed_hash(self):
  criteria={'rule':'550','host':'EXAMPLE','object':'/etc/example/status','sha256':'a'*64}
  key=self.store.save_pattern_policy('alert-rule',criteria,'Safe','Reviewed regular status-file updates','analyst')
  _,s=integrity_event('a'*64);s['timestamp']='2027-01-01T00:00:00Z'
  policy=decision_for(s,self.store.pattern_policies());self.assertEqual(policy['classification'],'Safe')
  _,changed=integrity_event('b'*64);self.assertIsNone(decision_for(changed,self.store.pattern_policies()))
  _,other=integrity_event('a'*64,path='/etc/example/different');self.assertIsNone(decision_for(other,self.store.pattern_policies()))
  _,other=integrity_event('a'*64,host='OTHER');self.assertIsNone(decision_for(other,self.store.pattern_policies()))
  self.store.disable_pattern_policy(key,'analyst');self.assertIsNone(decision_for(s,self.store.pattern_policies()));self.assertFalse(self.store.pattern_policies(True)[0]['enabled'])
 def test_suspicious_overrides_broader_safe(self):
  self.store.save_pattern_policy('alert-rule',{'rule':'550','host':'EXAMPLE','object':'/etc/example/status','sha256':'a'*64},'Safe','Reviewed this broad example pattern','analyst')
  self.store.save_pattern_policy('alert-rule',{'rule':'550','host':'EXAMPLE','object':'/etc/example/status'},'Suspicious','Unexpected change on the selected host','analyst')
  _,source=integrity_event('new');self.assertEqual(decision_for(source,self.store.pattern_policies())['classification'],'Suspicious')
  query=policy_filter(self.store.pattern_policies());self.assertIn('must_not',json.dumps(query));self.assertIn('EXAMPLE',json.dumps(query))
 def test_ip_port_source_scope_and_domain_boundaries(self):
  criteria={'destination_ip':'203.0.113.8','destination_port':'443','source_ip':'192.0.2.20'}
  self.store.save_pattern_policy('network-destination',criteria,'Suspicious','User reviewed traffic to this destination','analyst')
  source={'data':{'dest_ip':'203.0.113.8','dest_port':443,'src_ip':'192.0.2.20','tls':{'sni':'one.example'}}}
  self.assertEqual(decision_for(source,self.store.pattern_policies())['classification'],'Suspicious')
  source['data']['tls']['sni']='two.example';self.assertEqual(decision_for(source,self.store.pattern_policies())['classification'],'Suspicious')
  source['data']['dest_port']=8443;self.assertIsNone(decision_for(source,self.store.pattern_policies()))
  query=scope_query(self.store.pattern_policies()[0]);self.assertIn('data.win.eventdata.destinationPort',json.dumps(query))
 def test_scope_validation_rejects_wildcard_or_injected_fields(self):
  for kind,criteria in [('alert-rule',{'rule':'*'}),('network-destination',{'destination_ip':'203.0.113.0/24'}),('network-destination',{'destination_ip':'example.test'}),('alert-rule',{'rule':'550','arbitrary.field':'*'}),('network-destination',{'destination_ip':'203.0.113.8','destination_port':'70000'})]:
   with self.assertRaises(ValueError):validate_criteria(kind,criteria)
 def test_decision_is_idempotent_audited_and_updates_in_place(self):
  key=self.store.save_pattern_policy('alert-rule',{'rule':'550','host':'EXAMPLE','object':'/etc/example/status','sha256':'a'*64},'Safe','Reviewed broad test example rationale','analyst')
  same=self.store.save_pattern_policy('alert-rule',{'rule':'550','host':'EXAMPLE','object':'/etc/example/status','sha256':'a'*64},'Suspicious','Changed assessment based on new evidence','analyst')
  self.assertEqual(key,same);self.assertEqual(len(self.store.pattern_policies()),1);self.assertEqual(len(self.store.annotations('pattern:'+key)['history']),2)
 def test_sensor_signature_scope_does_not_dismiss_other_signatures(self):
  self.store.save_pattern_policy('alert-rule',{'rule':'86601','host':'EXAMPLE','signature':'Example expected signature','source_ip':'192.0.2.20','destination_ip':'203.0.113.8','destination_port':'443','protocol':'TCP'},'Safe','Reviewed this one exact sensor signature','analyst')
  s={'agent':{'name':'EXAMPLE'},'rule':{'id':'86601'},'data':{'src_ip':'192.0.2.20','dest_ip':'203.0.113.8','dest_port':'443','proto':'TCP','alert':{'signature':'Example expected signature'}}}
  self.assertEqual(decision_for(s,self.store.pattern_policies())['classification'],'Safe')
  s['data']['alert']['signature']='Different signature';self.assertIsNone(decision_for(s,self.store.pattern_policies()))
 def test_configuration_check_scope_is_exact(self):
  self.store.save_pattern_policy('alert-rule',{'rule':'19007','host':'EXAMPLE','check':'Example check'},'Safe','Reviewed one explicit configuration exception','analyst')
  s={'agent':{'name':'EXAMPLE'},'rule':{'id':'19007'},'data':{'sca':{'check':{'title':'Example check'}}}}
  self.assertEqual(decision_for(s,self.store.pattern_policies())['classification'],'Safe')
  s['data']['sca']['check']['title']='Another check';self.assertIsNone(decision_for(s,self.store.pattern_policies()))
 def test_network_bytes_only_count_flow_records(self):
  q=traffic_query([{'match_all':{}}]);self.assertIn({'term':{'data.event_type':'flow'}},q['query']['bool']['filter'])
  self.assertEqual(q['size'],0);self.assertIn('cardinality',q['aggs']['destinations']['aggs']['flow_count'])

if __name__=='__main__':unittest.main()
