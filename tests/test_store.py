import pathlib,sys,tempfile,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'backend'))
from store import Store,StateConflict

class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.s=Store(str(pathlib.Path(self.temp.name)/'soc.db'));self.s.initialize('admin','test-password-only')
    def tearDown(self):self.temp.cleanup()
    def test_auth_and_revocation(self):
        self.assertIsNone(self.s.login('admin','wrong'));u=self.s.login('admin','test-password-only');self.assertTrue(self.s.session(u['token']))
        self.s.save_user('admin','updated-password','admin',False,'admin');self.assertIsNone(self.s.session(u['token']))
    def test_last_admin_preserved(self):
        with self.assertRaises(ValueError):self.s.save_user('admin','','viewer',False,'admin')
    def test_notes_and_evidence_are_literal(self):
        cid=self.s.save_case(None,'test','','New','','admin');self.s.note(cid,"<script>alert('untrusted')</script>",'admin')
        self.assertEqual(self.s.case(cid)['notes'][0]['body'],"<script>alert('untrusted')</script>")
    def test_atomic_evidence_copy_and_duplicate_pin(self):
        cid=self.s.save_case(None,'test','','New','','admin');e={'key':'a','ref':{'index':'wazuh-alerts-test','id':'1'}}
        self.s.pin(cid,e,{'record':'original'},'admin');self.s.pin(cid,e,{'record':'original'},'admin')
        result=self.s.case(cid);self.assertEqual(len(result['evidence']),1);self.assertEqual(len(result['evidence'][0]['digest']),64)

    def test_bulk_clear_and_undo_preserve_assignment(self):
        self.s.state('one','Investigating','analyst-a','admin');old=self.s.states(['one'])['one']
        result=self.s.clear_alerts([{'key':'one','index':'wazuh-alerts-test','eid':'1','expected_status':'Investigating','expected_updated':old['updated']},{'key':'two','index':'wazuh-alerts-test','eid':'2','expected_status':'New','expected_updated':None}],'admin')
        self.assertEqual(result['count'],2);self.assertEqual(self.s.states(['one'])['one']['assignee'],'analyst-a')
        self.s.undo_clear(result['batch_id'],'admin');self.assertEqual(self.s.states(['one'])['one']['status'],'Investigating');self.assertEqual(self.s.states(['two'])['two']['status'],'New')
        self.assertEqual([h['action'] for h in self.s.annotations('one')['history']][-2:],['Alert cleared','Alert clear undone'])

    def test_stale_selection_rolls_back_the_entire_batch(self):
        self.s.state('two','Investigating','','other')
        with self.assertRaises(StateConflict):self.s.clear_alerts([{'key':'one','index':'wazuh-alerts-test','eid':'1','expected_status':'New','expected_updated':None},{'key':'two','index':'wazuh-alerts-test','eid':'2','expected_status':'New','expected_updated':None}],'admin')
        self.assertNotIn('one',self.s.states());self.assertEqual(self.s.states(['two'])['two']['status'],'Investigating')

    def test_undo_does_not_overwrite_later_changes(self):
        result=self.s.clear_alerts([{'key':'one','index':'wazuh-alerts-test','eid':'1','expected_status':'New','expected_updated':None}],'admin')
        self.s.state('one','Investigating','other','other')
        with self.assertRaises(StateConflict):self.s.undo_clear(result['batch_id'],'admin')
        self.assertEqual(self.s.states(['one'])['one']['assignee'],'other')

if __name__=='__main__':unittest.main()
