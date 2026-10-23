import copy,json,pathlib,sys,tempfile,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'backend'))
from engine import normalize,process_graph,relation
from assessment import assess,grouping_signature,group_events
from correlation import evidence_sequence
from integrity import digest,verify
from store import Store,StateConflict
from topology import build_topology
from telemetry import observation_rows

G1='{12345678-1234-1234-1234-123456789abc}';G2='{87654321-1234-1234-1234-123456789abc}'
def record(eid='11',data=None,host='ENDPOINT',rule=None):
 source={'timestamp':'2026-10-23T00:00:00Z','agent':{'name':host},'data':{'win':{'system':{'eventID':eid,'channel':'Microsoft-Windows-Sysmon/Operational'},'eventdata':data or {}}},'rule':rule or {'id':'100','level':15,'description':'Example detection'}}
 hit={'_index':'wazuh-alerts-test','_id':eid,'_source':source}
 return assess(normalize(hit),source),source

class ReviewTests(unittest.TestCase):
 def test_probe_assessment_requires_expected_creator(self):
  e,s=record(data={'targetFilename':r'C:\Users\example\AppData\Local\Temp\__PSScriptPolicyTest_random.psm1','image':r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'})
  self.assertEqual(e['assessment']['posture'],'Compatible with expected behavior');self.assertEqual(e['level'],15)
  e,s=record(data={'targetFilename':r'C:\Temp\__PSScriptPolicyTest_random.ps1','image':r'C:\Temp\powershell.exe'})
  self.assertEqual(e['assessment']['posture'],'Creator identity requires review')
 def test_material_changes_form_separate_groups(self):
  e,s=record('1',{'image':r'C:\Windows\System32\sdbinst.exe','commandLine':'sdbinst.exe one.sdb','user':r'EXAMPLE\analyst'})
  key,_=grouping_signature(e,s)
  for field,value in [('commandLine','sdbinst.exe two.sdb'),('user',r'EXAMPLE\other'),('hashes','SHA256=changed'),('parentCommandLine','changed parent')]:
   other=copy.deepcopy(s);other['data']['win']['eventdata'][field]=value
   event=assess(normalize({'_source':other}),other);self.assertNotEqual(key,grouping_signature(event,other)[0])
  other=copy.deepcopy(s);other['agent']['name']='OTHER'
  event=assess(normalize({'_source':other}),other);groups=group_events([(e,s),(event,other)],{})
  self.assertEqual(len(groups),1);self.assertEqual(groups[0]['hosts'],['ENDPOINT','OTHER'])
 def test_powershell_script_content_distinguishes_variants(self):
  a,s=record('4104',{'scriptBlockText':'Write-Output one'});b,t=record('4104',{'scriptBlockText':'Write-Output two'})
  self.assertNotEqual(grouping_signature(a,s)[0],grouping_signature(b,t)[0])
 def test_guid_tree_collects_file_registry_network_and_commands(self):
  parent,_=record('1',{'processGuid':G1,'image':'parent.exe','commandLine':'parent.exe full command'})
  child,_=record('1',{'processGuid':G2,'parentProcessGuid':G1,'image':'child.exe','commandLine':'child.exe full command'})
  file,_=record('11',{'processGuid':G2,'targetFilename':'example.txt'})
  registry,_=record('13',{'processGuid':G2,'targetObject':r'HKCU\Software\Example'})
  network,_=record('3',{'processGuid':G2,'sourceIp':'192.0.2.10','destinationIp':'192.0.2.20'})
  graph=process_graph([parent,child,file,registry,network]);node=next(n for n in graph['nodes'] if n['guid']==G2.strip('{}'))
  self.assertEqual(node['command'],'child.exe full command');self.assertEqual(len(node['events']),4);self.assertTrue(node['observed']);self.assertEqual(len(graph['edges']),1)
  self.assertEqual(relation(child,file)['strength'],'identifier')
 def test_missing_creation_and_runtime_are_explicit(self):
  image,_=record('7',{'processGuid':G2,'imageLoaded':'runtime.dll'})
  sequence=evidence_sequence(image,[image]);runtime=next(s for s in sequence['stages'] if s['id']=='managed_runtime')
  self.assertEqual(runtime['count'],0);self.assertIn('Not observed',runtime['status']);self.assertFalse(process_graph([image])['nodes'][0]['observed'])
 def test_integrity_detects_changed_snapshot_and_duplicate_conflict(self):
  with tempfile.TemporaryDirectory() as folder:
   store=Store(str(pathlib.Path(folder)/'test.db'));cid=store.save_case(None,'Example','','New','','analyst');event,source=record()
   store.pin(cid,event,source,'analyst');store.pin(cid,event,source,'analyst');case=store.case(cid)
   self.assertEqual(len(case['evidence']),1);self.assertTrue(case['evidence'][0]['integrity']['matches'])
   changed=copy.deepcopy(source);changed['extra']='changed'
   self.assertFalse(verify({'source':changed},digest(source))['matches'])
   with self.assertRaises(StateConflict):store.pin(cid,event,changed,'analyst')
 def test_topology_uses_other_environment_manifest_and_does_not_invent(self):
  manifest={'label':'Another environment','services':[{'id':'search','name':'Remote search','host':'search.example.test','unit':'search','observation':'remote.json','url':'https://search.example.test','lane':1}],'nodes':[{'id':'clients','name':'Example clients','lane':0}],'flows':[{'source_id':'clients','target_id':'search','data':'Example flow'}]}
  result=build_topology(manifest,{'remote.json':{'updated':123,'units':{'search':{'ActiveState':'active'}}}})
  self.assertEqual(result['services'][0]['state'],'active');self.assertEqual(result['services'][0]['host'],'search.example.test');self.assertEqual(len(result['flows']),1)
  self.assertEqual(build_topology({},{} )['services'],[]);self.assertFalse(build_topology({},{} )['configured'])
 def test_registered_agent_is_not_equivalent_to_telemetry(self):
  rows=observation_rows({'inventory':{'data':[{'name':'OFFLINE','status':'Active','os_name':'Windows'}]}},{},{})
  self.assertTrue(rows[0]['registered']);self.assertEqual(rows[0]['raw_count'],0);self.assertTrue(all(s['count']==0 for s in rows[0]['signals']))
 def test_expected_pattern_assessment_is_audited_and_reversible(self):
  with tempfile.TemporaryDirectory() as folder:
   store=Store(str(pathlib.Path(folder)/'test.db'));key='a'*64
   store.classify_group(key,'Expected recurrence','Verified normal maintenance activity','analyst');self.assertEqual(store.group_decisions()[key]['actor'],'analyst')
   store.classify_group(key,'Unreviewed','Reopen assessment for review','analyst');self.assertNotIn(key,store.group_decisions());self.assertEqual(len(store.annotations('group:'+key)['history']),2)

if __name__=='__main__':unittest.main()
