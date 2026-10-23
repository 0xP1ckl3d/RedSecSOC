import base64
import pathlib
import sys
import unittest

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'backend'))
from engine import normalize, decoded_literals, process_graph, relation, script_fragments,focus_evidence

G1='{12345678-1234-1234-1234-123456789abc}'
G2='{87654321-1234-1234-1234-123456789abc}'


def event(eid='1',data=None,host='TEST',channel='Microsoft-Windows-Sysmon/Operational',rule=None):
    return {'_index':'wazuh-alerts-4.x-test','_id':'test-'+eid,'_source':{'timestamp':'2026-10-23T00:00:00Z','id':eid,'agent':{'name':host,'id':'999'},'data':{'win':{'system':{'eventID':eid,'channel':channel},'eventdata':data or {}}},**({'rule':rule} if rule else {})}}


class EvidenceTests(unittest.TestCase):
    def test_unknown_decoder_preserves_all_fields(self):
        hit={'_source':{'timestamp':'2026-10-23T00:00:00Z','agent':{'name':'test'},'data':{'new_vendor':{'object':'object-7','decision':'denied','nested':[{'a':1}]}},'rule':{'id':'999999','level':15,'description':'New vendor rule'}}}
        e=normalize(hit)
        fields={i['field'] for rows in e['evidence'].values() for i in rows}
        self.assertTrue({'data.new_vendor.object','data.new_vendor.decision','data.new_vendor.nested'}<=fields)
        self.assertTrue(any('No specialized' in x for x in e['gaps']))
        self.assertFalse(any('malware executed' in x for x in e['observations']))

    def test_unseen_rule_promotes_its_actual_evidence(self):
        source={'data':{'vendor_xyz':{'criticalObject':'new-object','payload':'recorded payload'}},'rule':{'id':'999001','level':12}}
        rules={'rules':[{'id':'999001','conditions':[{'kind':'field','name':'vendor_xyz.criticalObject','value':'new-object'},{'kind':'field','name':'vendor_xyz.payload','value':'recorded'}]}]}
        e,r=focus_evidence(normalize({'_source':source}),source,rules)
        self.assertEqual(e['focus'][0]['value'],'new-object')
        self.assertEqual(e['focus'][1]['value'],'recorded payload')
        self.assertIn('contains the literal',r['explanations'][1])

    def test_absent_condition_field_is_not_invented(self):
        source={'data':{},'rule':{'id':'999002'}}
        e,r=focus_evidence(normalize({'_source':source}),source,{'rules':[{'id':'999002','conditions':[{'kind':'field','name':'missingPayload','value':'text'}]}]})
        self.assertEqual(e['focus'],[]);self.assertIn('not present',r['explanations'][0])

    def test_powershell_static_literal_and_path(self):
        payload=base64.b64encode(b'Write-Output "TEST_ONLY"').decode()
        script=f"$f=[IO.File]::Open('C:\\ProgramData\\test.ps1',[IO.FileMode]::Append);$v=[Convert]::FromBase64String('{payload}')"
        e=normalize(event('4104',{'scriptBlockText':script,'scriptBlockId':'test'},channel='Microsoft-Windows-PowerShell/Operational'))
        self.assertEqual(e['family'],'PowerShell');self.assertIn('test.ps1',e['subject'])
        self.assertEqual(decoded_literals(e)[0]['content'],'Write-Output "TEST_ONLY"')
        self.assertTrue(any(i['value']==script for i in e['evidence']['Script']))

    def test_encoded_command_utf16(self):
        literal=base64.b64encode('Write-Output TEST'.encode('utf-16-le')).decode()
        e=normalize(event(data={'commandLine':'powershell -enc '+literal}))
        self.assertEqual(decoded_literals(e)[0]['content'],'Write-Output TEST')

    def test_pid_reuse_does_not_invent_tree(self):
        a=normalize(event(data={'processId':'100','parentProcessId':'99','image':'a.exe'}))
        b=normalize(event('3',{'processId':'100','image':'unrelated.exe'}))
        self.assertEqual(process_graph([a,b])['nodes'],[])
        self.assertEqual(relation(a,b)['strength'],'context')

    def test_guid_links_are_scoped_to_host(self):
        a=normalize(event(data={'processGuid':G1,'image':'parent.exe'}))
        b=normalize(event(data={'processGuid':G2,'parentProcessGuid':G1,'image':'child.exe'},host='OTHER'))
        g=process_graph([a,b]);self.assertEqual(len(g['nodes']),3)
        self.assertEqual(relation(a,b)['strength'],'context')
        self.assertTrue(all(edge['parent'].startswith('OTHER|') for edge in g['edges']))

    def test_parent_missing_is_explicit(self):
        child=normalize(event(data={'processGuid':G2,'parentProcessGuid':G1,'image':'child.exe'}))
        g=process_graph([child]);self.assertEqual(len(g['edges']),1)
        parent=next(n for n in g['nodes'] if n['guid']==G1.strip('{}'))
        self.assertFalse(parent['observed']);self.assertIn('not found',parent['notice'])

    def test_script_does_not_silently_reconstruct_missing_fragment(self):
        a=normalize(event('4104',{'scriptBlockId':'A','scriptBlockText':'part1','messageNumber':'1','messageTotal':'2'},channel='PowerShell'))
        r=script_fragments(a,[a]);self.assertFalse(r['complete']);self.assertIsNone(r['content'])
        b=normalize(event('4104',{'scriptBlockId':'A','scriptBlockText':'part2','messageNumber':'2','messageTotal':'2'},channel='PowerShell'))
        r=script_fragments(a,[a,b]);self.assertTrue(r['complete']);self.assertEqual(r['content'],'part1part2')

    def test_file_integrity_keeps_before_after(self):
        e=normalize({'_source':{'syscheck':{'path':'/etc/test','event':'modified','sha256_before':'aaa','sha256_after':'bbb','changed_attributes':['sha256']},'rule':{'id':'550','level':7}}})
        self.assertEqual(e['family'],'File integrity');self.assertEqual(e['subject'],'/etc/test')
        self.assertEqual(e['evidence']['Before'][0]['value'],'aaa');self.assertEqual(e['evidence']['After'][0]['value'],'bbb')

    def test_task_definition_extracts_execution(self):
        e=normalize(event('4698',{'taskName':'test','taskContent':'<Task xmlns="urn:test"><Actions><Exec><Command>C:\\test.exe</Command><Arguments>--safe</Arguments></Exec></Actions></Task>'},channel='Security'))
        self.assertTrue(any(i['value']=='C:\\test.exe' for i in e['evidence']['Task actions']))

    def test_container_image_and_name_lead_quick_summary(self):
        e=normalize({'_source':{'data':{'integration':'redsec_docker','actor_id':'a'*64,'image':'gitea/gitea:1.28.2','name':'gitea','action':'start'}}})
        self.assertEqual(e['subject'],'gitea/gitea:1.28.2 · gitea')
        self.assertEqual(e['facts'][0]['label'],'Container image');self.assertEqual(e['facts'][0]['value'],'gitea/gitea:1.28.2')

    def test_docker_native_schema_and_missing_image(self):
        e=normalize({'_source':{'decoder':{'name':'docker'},'data':{'Actor':{'ID':'a'*64,'Attributes':{'name':'test','image':'nginx:stable'}},'Action':'stop'}}})
        self.assertEqual(e['subject'],'nginx:stable · test')
        e=normalize({'_source':{'data':{'integration':'redsec_docker','actor_id':'a'*64,'name':'test'}}})
        self.assertEqual(e['subject'],'test');self.assertTrue(any('not recorded' in gap for gap in e['gaps']))

    def test_bad_numbers_do_not_break_unknown_content(self):
        e=normalize(event('4104',{'scriptBlockText':'test','messageTotal':'malformed'},channel='PowerShell',rule={'level':None}))
        self.assertEqual(e['level'],0)

    def test_network_collector_not_attributed_as_endpoint(self):
        hit={'_source':{'agent':{'name':'EXAMPLE-SENSOR'},'data':{'src_ip':'192.0.2.10','dest_ip':'192.0.2.50','event_type':'alert','alert':{'signature':'TEST'}},'rule':{'id':'86601'}}}
        e=normalize(hit);self.assertEqual(e['identity']['source_ip'],'192.0.2.10')
        self.assertTrue(any('not necessarily' in x for x in e['observations']))

if __name__=='__main__':unittest.main()
