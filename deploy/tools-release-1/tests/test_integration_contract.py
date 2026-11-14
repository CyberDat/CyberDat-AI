import copy,importlib.util,json,sys,unittest
from pathlib import Path
D=Path(__file__).resolve().parents[1];sys.path.insert(0,str(D));s=importlib.util.spec_from_file_location('integration',D/'deploy-theme.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Integration(unittest.TestCase):
 def setUp(self):
  self.parent=json.loads((D/'integration-parent.json').read_text());self.spec={**self.parent,'base':copy.deepcopy(self.parent['target']),'target':copy.deepcopy(self.parent['target']),'revision':m.INTEGRATION_REVISION,'parent_archive_sha256':m.INTEGRATION_PARENT_ARCHIVE}
  for n in ['inc/tools.php','page-templates/tool.php']:self.spec['target'][n]['sha256']='a'*64
 def test_two_file_delta(self):self.assertTrue(m.approved_release(self.spec,self.parent))
 def test_no_third_file(self):self.spec['target']['page-templates/tools.php']['sha256']='b'*64;self.assertFalse(m.approved_release(self.spec,self.parent))
 def test_no_missing_file(self):self.spec['target'].pop('functions.php');self.assertFalse(m.approved_release(self.spec,self.parent))
 def test_parent_required(self):self.assertFalse(m.approved_release(self.spec))
 def test_parent_archive(self):self.parent['archive_sha256']='b'*64;self.assertFalse(m.approved_release(self.spec,self.parent))
 def test_research_pin(self):self.spec['research_commit']='a'*40;self.assertFalse(m.approved_release(self.spec,self.parent))
 def test_four_editorial_pages_and_unique_seo(self):
  d=json.loads((D/'editorial-integration.json').read_text());self.assertEqual(len(d),4);self.assertEqual(len({x['seo']['title'] for x in d.values()}),4);self.assertEqual(len({x['seo']['description'] for x in d.values()}),4)
  for p in d.values():
   self.assertEqual(len(p['questions']),4);self.assertNotIn('<h1',p['article']);self.assertNotIn('<script',p['article']);self.assertGreater(len(p['article']),3000)

class Canonical(unittest.TestCase):
 def setUp(self):
  self.parent=json.loads((D/'canonical-parent.json').read_text());self.spec={**self.parent,'base':copy.deepcopy(self.parent['target']),'target':copy.deepcopy(self.parent['target']),'revision':m.CANONICAL_REVISION,'parent_archive_sha256':m.CANONICAL_PARENT_ARCHIVE};self.spec['target']['inc/tools.php']['sha256']='a'*64
 def test_canonical_only(self):self.assertTrue(m.approved_release(self.spec,self.parent))
 def test_refuse_template_change(self):self.spec['target']['page-templates/tool.php']['sha256']='b'*64;self.assertFalse(m.approved_release(self.spec,self.parent))
 def test_refuse_wrong_parent(self):self.parent['archive_sha256']='b'*64;self.assertFalse(m.approved_release(self.spec,self.parent))
 def test_refuse_unknown_file(self):self.spec['target']['unexpected.php']={'sha256':'a'*64};self.assertFalse(m.approved_release(self.spec,self.parent))
 def test_refuse_research_change(self):self.spec['research_commit']='b'*40;self.assertFalse(m.approved_release(self.spec,self.parent))

if __name__=='__main__':unittest.main(verbosity=2)
