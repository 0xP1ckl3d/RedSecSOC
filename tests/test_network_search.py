import pathlib,sys,unittest,json
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'backend'))
from engine import normalize
from network import enrich_network
from search import terms_query,SEARCH_FIELDS,network_filter,port_filter,protocol_filter

ASSETS={'updated':123,'addresses':{'192.0.2.103':{'name':'WS01','source':'Current Wazuh agent inventory','observed':123},'192.0.2.10':{'name':'DC01','source':'Current Wazuh agent inventory','observed':123}}}
def event(data,rule=None):
 s={'timestamp':'2026-10-23T00:00:00Z','agent':{'name':'EXAMPLE-SENSOR'},'data':data}
 if rule:s['rule']=rule
 h={'_index':'wazuh-archives-test','_id':'one','_source':s};return enrich_network(normalize(h),s,ASSETS)

class NetworkSearchTests(unittest.TestCase):
 def test_recorded_smb_and_asset_names_lead_title(self):
  e=event({'event_type':'flow','app_proto':'smb','src_ip':'192.0.2.103','dest_ip':'192.0.2.10','dest_port':445})
  self.assertEqual(e['title'],'Network activity: SMB from WS01 to DC01');self.assertFalse(e['network_context']['service_inferred'])
  self.assertIn('192.0.2.103',e['facts'][0]['value']);self.assertEqual(e['host'],'EXAMPLE-SENSOR')
  self.assertEqual(e['facts'][2]['label'],'Destination port');self.assertEqual(e['facts'][2]['value'],445)
 def test_tls_enrichment_preserves_both_ports_and_addresses_in_quick_facts(self):
  e=event({'event_type':'tls','app_proto':'tls','proto':'TCP','src_ip':'192.0.2.103','dest_ip':'203.0.113.5','src_port':51000,'dest_port':443})
  facts={f['label']:f['value'] for f in e['facts'][:6]}
  self.assertEqual(facts['Destination port'],443);self.assertEqual(facts['Source port'],51000)
  self.assertEqual(facts['Application protocol'],'TLS');self.assertEqual(facts['Transport'],'TCP')
  self.assertIn('192.0.2.103',facts['Source endpoint']);self.assertIn('203.0.113.5',facts['Destination endpoint'])
 def test_port_estimate_is_explicit_and_unknown_ip_retained(self):
  e=event({'event_type':'flow','proto':'TCP','src_ip':'192.0.2.103','dest_ip':'203.0.113.5','dest_port':445})
  self.assertEqual(e['title'],'Network activity: Possible SMB from WS01 to 203.0.113.5');self.assertTrue(e['network_context']['service_inferred'])
 def test_alert_title_and_identity_are_preserved(self):
  data={'event_type':'alert','app_proto':'smb','src_ip':'192.0.2.103','dest_ip':'192.0.2.10','alert':{'signature':'Original detection'}}
  e=event(data,{'id':'111','level':12,'description':'Original rule classification'})
  self.assertEqual(e['title'],'Original rule classification');self.assertEqual(e['subject'],'SMB from WS01 to DC01')
 def test_recorded_protocol_wins_over_port_guess(self):
  e=event({'event_type':'http','app_proto':'http','src_ip':'192.0.2.103','dest_ip':'192.0.2.10','dest_port':445})
  self.assertEqual(e['network_context']['service'],'HTTP');self.assertFalse(e['network_context']['service_inferred'])
 def test_recorded_hostname_wins_and_sni_provenance_is_explicit(self):
  e=event({'event_type':'tls','src_ip':'192.0.2.103','dest_ip':'203.0.113.1','tls':{'sni':'example.test'}})
  self.assertIn('example.test',e['title']);self.assertIn('Requested server name',e['network_context']['destination']['basis'])
 def test_missing_endpoints_do_not_invent_a_flow(self):
  e=event({'event_type':'stats','stats':{'packets':1}});self.assertNotIn('network_context',e)
 def test_partial_title_and_keyword_search_is_case_insensitive(self):
  q=terms_query('EXE',['rule.description','data.win.eventdata.image'],ASSETS)
  self.assertEqual(q['bool']['should'][0],{'wildcard':{'rule.description':{'value':'*EXE*','case_insensitive':True}}})
 def test_hostname_search_includes_network_addresses(self):
  q=json.dumps(terms_query('WS01',['full_log'],ASSETS));self.assertIn('192.0.2.103',q);self.assertIn('data.dest_ip',q)
 def test_boolean_grouping_and_quoted_paths(self):
  q=terms_query('EXE AND (WS01 OR "C:\\Program Files")',['full_log'],ASSETS)
  self.assertIn('must',q['bool']);self.assertEqual(len(q['bool']['must']),2)
  with self.assertRaises(ValueError):terms_query('EXE AND',['full_log'],ASSETS)
  with self.assertRaises(ValueError):terms_query('"unclosed',['full_log'],ASSETS)
 def test_query_clause_budget_and_network_filters(self):
  self.assertLess(len(SEARCH_FIELDS)*6+100,1024)
  self.assertIn('sourcePort',json.dumps(port_filter(445)));self.assertIn('smb2',json.dumps(protocol_filter('SMB')))
  self.assertNotIn('EXAMPLE-SENSOR',json.dumps(network_filter()))

if __name__=='__main__':unittest.main()
