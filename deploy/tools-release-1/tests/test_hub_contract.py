import copy,importlib.util,json,sys,unittest
from pathlib import Path
D=Path(__file__).resolve().parents[1];sys.path.insert(0,str(D));s=importlib.util.spec_from_file_location('live',D/'deploy-theme.py');live=importlib.util.module_from_spec(s);s.loader.exec_module(live)
class Contract(unittest.TestCase):
 def setUp(self):
  self.parent=json.loads((D/'manifest.json').read_text());self.spec={**self.parent,'base':copy.deepcopy(self.parent['target']),'target':copy.deepcopy(self.parent['target']),'revision':live.HUB_REVISION,'parent_archive_sha256':live.PARENT_ARCHIVE};self.spec['target']['page-templates/tools.php']['sha256']='a'*64
 def test_original(self):self.assertTrue(live.approved_release(self.parent))
 def test_exact_template_delta(self):self.assertTrue(live.approved_release(self.spec,self.parent))
 def test_requires_parent(self):self.assertFalse(live.approved_release(self.spec))
 def test_refuses_unknown_upgrade(self):self.spec.pop('revision');self.assertFalse(live.approved_release(self.spec,self.parent))
 def test_refuses_second_file(self):self.spec['target']['functions.php']['sha256']='b'*64;self.assertFalse(live.approved_release(self.spec,self.parent))
 def test_refuses_wrong_parent(self):self.parent['archive_sha256']='c'*64;self.assertFalse(live.approved_release(self.spec,self.parent))
 def test_refuses_removed_file(self):self.spec['target'].pop('functions.php');self.assertFalse(live.approved_release(self.spec,self.parent))
 def test_refuses_research_change(self):self.spec['research_commit']='d'*40;self.assertFalse(live.approved_release(self.spec,self.parent))
if __name__=='__main__':unittest.main(verbosity=2)
