"""Exercise the exact permission repair with temporary files, no VPS operations."""
import hashlib,importlib.util,json,os,pathlib,stat,tempfile,types
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('css_delivery_finish',ROOT/'deploy/research-0.8.2/finish-admin-layout.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.pwd=types.SimpleNamespace(getpwnam=lambda _:types.SimpleNamespace(pw_uid=os.getuid()))
with tempfile.TemporaryDirectory(prefix='cyberdat-css-permissions-') as folder:
 base=pathlib.Path(folder);plugin=base/'plugin';parent=plugin/'assets';parent.mkdir(parents=True);parent.chmod(0o700);(plugin/'includes').mkdir();css=parent/'discovery-admin.css';css.write_text('public css');php=plugin/'includes/discovery-admin.php';php.write_text('public PHP code');backup=base/'backup';backup.mkdir()
 patch={'css':hashlib.sha256(css.read_bytes()).hexdigest(),'after':hashlib.sha256(php.read_bytes()).hexdigest()};support=types.SimpleNamespace(PLUGIN=plugin)
 extra=parent/'unexpected-private.txt';extra.write_text('fixture')
 try:m.repair_assets(support,backup,patch);raise AssertionError('Unexpected contents accepted')
 except RuntimeError:pass
 assert stat.S_IMODE(parent.stat().st_mode)==0o700
 extra.unlink();m.repair_assets(support,backup,patch);assert stat.S_IMODE(parent.stat().st_mode)==0o755
 assert json.loads((backup/'asset-directory-mode-before.json').read_text())['mode']=='0700'
 m.repair_assets(support,backup,patch);assert css.read_text()=='public css' and php.read_text()=='public PHP code'
 assert stat.S_IMODE((backup/'asset-directory-mode-before.json').stat().st_mode)==0o600
print('PASS: only exact static directory repaired, unexpected contents refused, file bytes retained and repeat verification safe')
