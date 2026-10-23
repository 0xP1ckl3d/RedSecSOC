import copy,json,pathlib,sys,tempfile,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'backend'))
from engine import normalize
from addresses import classify_address
from patterns import address_context,validate_safe,decision_for,changed_scopes,scope_query,suggested_scope
from assessment import assess
from correlation import evidence_links,identity_sources,event_clock
from store import Store,StateConflict

G1='{12345678-1234-1234-1234-123456789abc}';G2='{87654321-1234-1234-1234-123456789abc}';G3='{abcdef12-1234-1234-1234-123456789abc}'
def win(key,eid,data,host='SOURCE',ip='192.0.2.20',second=0,channel='Microsoft-Windows-Sysmon/Operational'):
 s={'id':key,'timestamp':f'2026-10-23T00:00:{second:02d}Z','agent':{'name':host,'ip':ip},'rule':{'id':'92213','description':'Example detection','level':15},'data':{'win':{'system':{'channel':channel,'eventID':eid},'eventdata':data}}}
 return assess(normalize({'_index':'wazuh-alerts-test','_id':key,'_source':s}),s),s

class EvidenceLinksTests(unittest.TestCase):
 def test_address_taxonomy_and_inventory_independence(self):
  cases={'239.255.255.250':'multicast','224.0.0.1':'multicast','ff02::1':'multicast','10.1.2.3':'private','172.16.1.1':'private','192.168.1.2':'private','127.0.0.2':'loopback','::1':'loopback','169.254.1.1':'link-local','fe80::1':'link-local','100.64.1.1':'shared','0.0.0.0':'unspecified','::':'unspecified','255.255.255.255':'broadcast','240.0.0.1':'reserved','192.0.2.1':'documentation','2001:db8::1':'documentation','fc00::1':'unique-local','8.8.8.8':'public','not-an-ip':'invalid','::ffff:239.255.255.250':'multicast'}
  for address,kind in cases.items():
   with self.subTest(address=address):
    result=classify_address(address);self.assertEqual(result['address_class'],kind);self.assertEqual(result['external'],kind=='public')
  self.assertTrue(address_context('8.8.8.8',{'addresses':{'8.8.8.8':{'name':'Known public asset'}}})['external'])
  self.assertIn('1900',address_context('239.255.255.250',{})['service_hint'])
 def probe(self):
  return win('probe','11',{'targetFilename':r'C:\Users\example\AppData\Local\Temp\__PSScriptPolicyTest_abc.xyz.ps1','image':r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe','user':r'EXAMPLE\analyst','processGuid':G1})
 def test_safe_probe_template_groups_random_names_not_executables_or_other_context(self):
  event,source=self.probe();scope=suggested_scope(event,source);validate_safe('alert-rule',scope)
  policy={'id':'example','kind':'alert-rule','criteria':scope,'classification':'Safe','rationale':'Verified initialization','actor':'analyst','updated':1}
  for name in ('__PSScriptPolicyTest_second.ps1','__PSScriptPolicyTest_second.psm1'):
   s=copy.deepcopy(source);s['data']['win']['eventdata']['targetFilename']=scope['probe_prefix']+name.split('__PSScriptPolicyTest_')[1]
   self.assertEqual(decision_for(s,[policy])['classification'],'Safe')
  for field,value in [('targetFilename',r'C:\Users\example\AppData\Local\Temp\payload.exe'),('targetFilename',scope['probe_prefix']+'x.exe'),('targetFilename',scope['probe_prefix']+r'child\x.ps1'),('image',r'C:\Temp\powershell.exe'),('user',r'EXAMPLE\other')]:
   s=copy.deepcopy(source);s['data']['win']['eventdata'][field]=value
   self.assertIsNone(decision_for(s,[policy]));self.assertTrue(changed_scopes(s,[policy]))
  s=copy.deepcopy(source);del s['data']['win']['eventdata']['user'];self.assertIsNone(decision_for(s,[policy]))
  self.assertIn('regexp',json.dumps(scope_query(policy)))
 def test_broad_safe_rejected_and_network_must_be_bounded(self):
  for kind,c in [('alert-rule',{'rule':'92213'}),('alert-rule',{'rule':'92213','host':'SOURCE'}),('alert-rule',{'rule':'92213','host':'SOURCE','object':r'C:\Temp\payload.exe'}),('network-destination',{'destination_ip':'203.0.113.8'})]:
   with self.assertRaises(ValueError):validate_safe(kind,c)
 def test_recorded_field_provenance_and_naive_sysmon_utc_clock(self):
  event,source=win('clock','3',{'processGuid':G1,'utcTime':'2026-10-23 00:00:00.000','sourcePort':'52000'})
  provenance=identity_sources(source)
  self.assertEqual(provenance['process_guid'],{'field':'data.win.eventdata.processGuid','value':G1})
  self.assertEqual(provenance['source_port']['field'],'data.win.eventdata.sourcePort')
  self.assertEqual(event_clock(event),1792713600)
 def sequence(self):
  a,_=win('parent','1',{'processGuid':G1,'image':'example.exe'})
  b,_=win('child','1',{'processGuid':G2,'parentProcessGuid':G1,'image':'child.exe'})
  n,_=win('network','3',{'processGuid':G2,'sourceIp':'192.0.2.20','sourcePort':'52000','destinationIp':'192.0.2.10','destinationPort':'5985','protocol':'tcp','initiated':'true'},second=1)
  auth,_=win('auth','4624',{'ipAddress':'192.0.2.20','ipPort':'52000','targetLogonId':'0x123456','logonType':'3'},host='TARGET',ip='192.0.2.10',second=2,channel='Security')
  target,_=win('target','1',{'processGuid':G3,'logonId':'0x123456','image':'target.exe'},host='TARGET',ip='192.0.2.10',second=3)
  return a,b,n,auth,target
 def test_guid_child_network_remote_session_and_target_execution_join(self):
  events=self.sequence();result=evidence_links(events,events[0]);c=result['selected']
  self.assertEqual(len(c['event_keys']),5);self.assertTrue(c['cross_host']);self.assertTrue(c['candidate'])
  self.assertTrue({'parent','identifier','remote-session','session'}<={e['kind'] for e in c['edges']})
  for edge in c['edges']:self.assertTrue(edge['source_ref']);self.assertTrue(edge['target_ref']);self.assertTrue(edge['fields'])
 def test_shared_ip_or_pid_or_time_does_not_join_unrelated_execution(self):
  seed=self.sequence()[0];other,_=win('other','1',{'processId':'100','processGuid':G3,'image':'other.exe'})
  self.assertIsNone(evidence_links([seed,other],seed)['selected'])
 def test_remote_session_rejects_wrong_port_time_host_and_protocol(self):
  for field,value in [('source_port','52001'),('destination_ip','192.0.2.99'),('protocol','udp')]:
   events=copy.deepcopy(self.sequence());events[2]['identity'][field]=value
   c=evidence_links(events,events[0])['selected'];self.assertNotIn('TARGET',c['hosts'])
  events=copy.deepcopy(self.sequence());events[3]['time']='2026-10-23T00:05:00Z'
  self.assertNotIn('TARGET',evidence_links(events,events[0])['selected']['hosts'])
 def test_same_guid_on_another_host_is_not_same_process(self):
  a,b,*_=self.sequence();b=copy.deepcopy(b);b['host']='OTHER';b['identity']['process_guid']=a['identity']['process_guid'];b['identity']['parent_guid']=''
  self.assertIsNone(evidence_links([a,b],a)['selected'])
 def test_builtin_sessions_and_conflicting_logon_guids_are_rejected(self):
  a,b,*_=self.sequence();b['identity']['parent_guid']='';a['identity']['logon_id']=b['identity']['logon_id']='0x3e7'
  self.assertIsNone(evidence_links([a,b],a)['selected'])
  a['identity']['logon_id']=b['identity']['logon_id']='0x555';a['identity']['logon_guid']='first';b['identity']['logon_guid']='second'
  self.assertIsNone(evidence_links([a,b],a)['selected'])
 def test_five_tuple_reuse_outside_recorded_time_is_not_joined(self):
  a=self.sequence()[2];b=copy.deepcopy(a);b.update(key='sensor',host='SENSOR',ref={'index':'wazuh-archives-test','id':'sensor'});b['identity']['process_guid']=''
  self.assertTrue(any(e['kind']=='flow' for e in evidence_links([a,b],a)['edges']))
  b['time']='2026-10-23T01:00:01Z';self.assertIsNone(evidence_links([a,b],a)['selected'])
  b['identity'].update(flow_start='2026-10-23T00:00:00Z',flow_end='2026-10-23T01:00:01Z')
  self.assertTrue(any(e['kind']=='flow' for e in evidence_links([a,b],a)['edges']))
 def test_shared_broker_parent_does_not_group_sibling_programs(self):
  a,b,*_=self.sequence();a['identity']['image']=r'C:\Windows\System32\services.exe'
  self.assertIsNone(evidence_links([a,b],b)['selected'])
 def test_old_broad_safe_is_disabled_with_audit_once(self):
  with tempfile.TemporaryDirectory() as folder:
   path=str(pathlib.Path(folder)/'db');store=Store(path)
   with store.db() as db:db.execute('INSERT INTO pattern_policies VALUES(?,?,?,?,?,?,?,1)',('old','alert-rule','{"rule":"92213"}','Safe','Old broad decision','analyst',1))
   migrated=Store(path);self.assertFalse(migrated.pattern_policies());self.assertEqual(migrated.annotations('pattern:old')['history'][0]['action'],'Safe scope requires review')
   self.assertEqual(len(Store(path).annotations('pattern:old')['history']),1)
 def test_preservation_batch_is_atomic_and_has_source_digests(self):
  with tempfile.TemporaryDirectory() as folder:
   store=Store(str(pathlib.Path(folder)/'db'));cid=store.save_case(None,'Example sequence','','Investigating','','analyst');a,source=self.probe()
   store.pin_sequence(cid,[(a,source)],{'correlation':{'id':'sequence','edges':[]}},'analyst');self.assertTrue(store.case(cid)['evidence'][0]['integrity']['matches'])
   changed=copy.deepcopy(source);changed['changed']=True;b,s=win('other','1',{'processGuid':G2})
   with self.assertRaises(StateConflict):store.pin_sequence(cid,[(b,s),(a,changed)],{'correlation':{'id':'sequence','edges':[]}},'analyst')
   self.assertEqual(len(store.case(cid)['evidence']),1);self.assertEqual(store.case_counts()['open'],1)

if __name__=='__main__':unittest.main()
