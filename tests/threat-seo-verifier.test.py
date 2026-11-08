"""Offline owner-tool tests. No sudo, HTTP, WordPress or DB calls."""
import contextlib,importlib.util,io,json,pathlib,types
path=pathlib.Path(__file__).resolve().parents[1]/'deploy/research/deploy-threat-2.py'
spec=importlib.util.spec_from_file_location('threat_verifier',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
expected='Explore CyberDat threat intelligence: verified CISA KEV & NVD.'
module.wp=lambda *args,**kwargs:types.SimpleNamespace(stdout=json.dumps({'id':44,'description':expected,'template':'page-templates/threat-intelligence.php','rank_math_active':True}).encode())
for name,head,passed in [
 ('standard','<head><meta name="description" content="Explore CyberDat threat intelligence: verified CISA KEV &amp; NVD."></head>',True),
 ('attribute order and HTML entities','<head><META content="Explore CyberDat threat intelligence&#58; verified CISA KEV &amp; NVD." NAME="Description"></head>',True),
 ('missing','<head></head>',False),
 ('duplicate','<head><meta name="description" content="a"><meta name="description" content="b"></head>',False),
 ('wrong content','<head><meta name="description" content="Another page"></head>',False),
 ('body not metadata','<head></head><body><meta name="description" content="Another page"></body>',False),
]:
 ok=True
 try:
  with contextlib.redirect_stdout(io.StringIO()):module.verify_description(head)
 except RuntimeError:ok=False
 assert ok is passed,name
 print('PASS: SEO verifier '+name)
print('PASS: no live calls, page writes or credentials involved')
