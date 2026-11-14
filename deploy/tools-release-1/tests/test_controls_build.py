"""Controls-only rebuild checks; no WordPress or real deploy entry point runs."""
import importlib.util,json,os,shutil,tempfile,unittest
from pathlib import Path
D=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('cb',D/'build-controls.py');cb=importlib.util.module_from_spec(s);s.loader.exec_module(cb)
class ControlsBuild(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.r=Path(self.tmp.name);self.src=self.r/'source';self.src.mkdir()
  for n in cb.FILES|{'controls-baseline-sha256.json','authorization.example.json'}:shutil.copyfile(D/n,self.src/n)
  self.auth=Path(os.environ['CYBERDAT_TEST_CONTROLS_AUTH']);self.package=Path(os.environ['CYBERDAT_TEST_CONTROLS_PACKAGE']);self.old=Path(os.environ['CYBERDAT_TEST_OLD_CONTROLS']);self.out=self.r/'out'
 def tearDown(self):self.tmp.cleanup()
 def build(self):return cb.build(self.src,self.old,D/'controls-source-approval.json',self.package,self.auth,self.out)
 def test_full_rebuild_and_verification(self):
  self.build();h=cb.verify(self.out);self.assertEqual(len(h),12);self.assertEqual(h['deploy-theme.py'],cb.sha(D/'deploy-theme.py'))
 def test_no_overwrite(self):
  self.out.mkdir()
  with self.assertRaises(RuntimeError):self.build()
 def test_unapproved_code(self):
  (self.src/'deploy-theme.py').write_text('raise Exception("unapproved")')
  with self.assertRaises(RuntimeError):self.build()
 def test_symlink_source(self):
  p=self.src/'route_policy.py';p.unlink();p.symlink_to(D/'route_policy.py')
  with self.assertRaises(RuntimeError):self.build()
 def test_wrong_baseline(self):
  (self.src/'controls-baseline-sha256.json').write_text('{}')
  with self.assertRaises(RuntimeError):self.build()
 def test_tamper_is_blocked(self):
  self.build();(self.out/'deploy-theme.py').write_text('changed')
  with self.assertRaises(RuntimeError):cb.verify(self.out)
 def test_extra_file_is_blocked(self):
  self.build();(self.out/'extra').write_text('unexpected')
  with self.assertRaises(RuntimeError):cb.verify(self.out)
 def test_reproducible_registry(self):
  self.build();first=(self.out/'controls-sha256.json').read_bytes();registry=(self.out/'source-controls-sha256.generated.json').read_bytes();self.out=self.r/'second';self.build();self.assertEqual(first,(self.out/'controls-sha256.json').read_bytes());self.assertEqual(registry,(self.out/'source-controls-sha256.generated.json').read_bytes())
if __name__=='__main__':unittest.main(verbosity=2)
