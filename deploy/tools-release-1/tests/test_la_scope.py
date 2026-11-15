"""Offline authorization-scope tests; never import a live WordPress instance."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
sys.dont_write_bytecode = True
D = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(D))
s = importlib.util.spec_from_file_location('la_scope', D / 'deploy-theme.py')
m = importlib.util.module_from_spec(s)
s.loader.exec_module(m)
from safe_theme import manifest


class Scope(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        full = manifest(D.parents[1] / 'wp-content/themes/cyberdat')
        target = {n: v for n, v in full.items() if n != 'assets/images/tools-hub/README.md'}
        # The actual parent package is supplied explicitly, never inferred from runtime.
        cls.parent = json.loads(Path(sys.argv_parent).read_text())
        cls.spec = {**cls.parent, 'revision': m.LA_REVISION, 'parent_archive_sha256': m.LA_PARENT_ARCHIVE,
                    'candidate_commit': m.LA_CANDIDATE, 'base': cls.parent['target'], 'target': target}

    def test_exact_six(self):
        self.assertTrue(m.approved_release(self.spec, self.parent))

    def reject(self, mutate):
        x = copy.deepcopy(self.spec)
        mutate(x)
        self.assertFalse(m.approved_release(x, self.parent))

    def test_hub_modification(self):
        self.reject(lambda x: x['target']['page-templates/tools.php'].update(sha256='0' * 64))

    def test_fifth_tool_addition(self):
        self.reject(lambda x: x['target'].update({'fifth.php': {'sha256': '0' * 64, 'bytes': 1, 'mode': '0644'}}))

    def test_deletion(self):
        self.reject(lambda x: x['target'].pop('functions.php'))

    def test_wrong_candidate(self):
        self.reject(lambda x: x.update(candidate_commit='3cbc111'))

    def test_wrong_six_bytes(self):
        self.reject(lambda x: x['target']['assets/js/log-anonymizer/engine.js'].update(sha256='0' * 64))

    def test_missing_one_delta(self):
        self.reject(lambda x: x['target'].update({'inc/tool-log-anonymizer.php': x['base']['inc/tool-log-anonymizer.php']}))

    def test_unknown_live_drift(self):
        self.reject(lambda x: x['base']['style.css'].update(sha256='0' * 64))

    def test_research_pin(self):
        self.reject(lambda x: x.update(research_commit='0' * 40))

    def test_wrong_parent(self):
        self.reject(lambda x: x.update(parent_archive_sha256='0' * 64))


if __name__ == '__main__':
    sys.argv_parent = sys.argv.pop(1)
    unittest.main()
