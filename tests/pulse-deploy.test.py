"""Static deployment boundary checks. Never invokes Docker, WordPress, network or sudo."""
import ast,pathlib,re
r=pathlib.Path(__file__).resolve().parents[1];p=r/'deploy/home-pulse/deploy-pulse.py';s=p.read_text();tree=ast.parse(s)
for token in ["m.database_backup(backup/'staging.sql.gz')","tarfile.open(backup/'theme.tar.gz'","m.atomic_copy(","research==m.research_code()","timers==m.timer_fingerprints()","untouched_before==untouched()","m.verify_description(full)","m.proof()","'--rollback'","'--verify'"]:
 assert token in s,token
calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call)]
for n in calls:
 if isinstance(n.func,ast.Attribute) and n.func.attr=='unit':assert all(not isinstance(a,ast.Constant) or a.value not in ['start','restart','reload','stop','disable','enable'] for a in n.args)
assert not re.search(r"wp\(['\"](?:post|option|plugin|cron|eval-file)",s)
assert s.index("m.database_backup(backup/'staging.sql.gz')")<s.index("for entry in sorted(targets")
js=(r/'wp-content/themes/cyberdat/assets/js/threat-pulse.js').read_text();assert not re.search(r'\b(fetch|XMLHttpRequest|WebSocket|localStorage|sessionStorage|innerHTML)\b',js)
css=(r/'wp-content/themes/cyberdat/assets/css/threat-pulse.css').read_text();assert css.startswith('/* Homepage-only');assert 'body.home .site-main.container' in css and 'prefers-reduced-motion' in css
ast.parse((r/'deploy/home-pulse/capture-pulse.py').read_text());print('PASS: backup before writes; explicit rollback; protected Research/timers/full Dashboard; no page networking or HTML injection sinks')
