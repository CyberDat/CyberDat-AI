import copy,importlib.util,json,sys,unittest
from pathlib import Path
D=Path(__file__).resolve().parents[1];sys.path.insert(0,str(D));s=importlib.util.spec_from_file_location('design_live',D/'deploy-theme.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Design(unittest.TestCase):
 def setUp(self):
  self.parent=json.loads((D/'design-parent.json').read_text());self.spec={**self.parent,'revision':m.DESIGN_REVISION,'parent_archive_sha256':m.DESIGN_PARENT_ARCHIVE,'theme_commit':m.DESIGN_SOURCE_COMMIT,'base':copy.deepcopy(self.parent['target']),'target':copy.deepcopy(self.parent['target'])}
  for n in m.DESIGN_MODIFIED:self.spec['target'][n]['sha256']='a'*64
  for n in m.DESIGN_ADDED:self.spec['target'][n]={'sha256':'b'*64,'bytes':1,'mode':'0644'}
 def test_exact_delta(self):self.assertTrue(m.approved_release(self.spec,self.parent))
 def test_no_parent(self):self.assertFalse(m.approved_release(self.spec))
 def test_wrong_parent(self):self.parent['archive_sha256']='b'*64;self.assertFalse(m.approved_release(self.spec,self.parent))
 def test_catalog_conflict(self):self.spec['target']['inc/tools-catalog.json']['sha256']='c'*64;self.assertFalse(m.approved_release(self.spec,self.parent))
 def test_fifth_tool_not_overwritten(self):self.spec['target']['functions.php']['sha256']='c'*64;self.assertFalse(m.approved_release(self.spec,self.parent))
 def test_engine_conflict(self):self.spec['target']['assets/js/log-anonymizer/engine.js']['sha256']='c'*64;self.assertFalse(m.approved_release(self.spec,self.parent))
 def test_no_delete(self):self.spec['target'].pop('functions.php');self.assertFalse(m.approved_release(self.spec,self.parent))
 def test_unapproved_asset(self):self.spec['target']['unexpected.svg']={'sha256':'c'*64};self.assertFalse(m.approved_release(self.spec,self.parent))
 def test_wrong_source(self):self.spec['theme_commit']='c'*40;self.assertFalse(m.approved_release(self.spec,self.parent))
 def test_wrong_research(self):self.spec['research_commit']='c'*40;self.assertFalse(m.approved_release(self.spec,self.parent))
if __name__=='__main__':unittest.main(verbosity=2)
