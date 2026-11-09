"""Static runtime/deployment boundaries; never invokes WordPress or network."""
import ast,pathlib,re
r=pathlib.Path(__file__).resolve().parents[1];p=r/'deploy/analytics-2.1';s=(p/'deploy-analytics.py').read_text();ast.parse(s);ast.parse((p/'capture-analytics.py').read_text())
assert s.index("m.database_backup(backup/'staging.sql.gz')")<s.index("m.wp('plugin','activate'")
assert "m.wp('plugin','deactivate','cyberdat-threat-analytics')" in s
assert "research==m.research_code()" in s and "timers==m.timer_fingerprints()" in s and "unchanged==untouched()" in s
for n in ast.walk(ast.parse(s)):
 if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='unit':assert n.args and isinstance(n.args[0],ast.Constant) and n.args[0].value=='show'
q=(r/'wp-content/plugins/cyberdat-threat-analytics/query.php').read_text();assert 'SET TRANSACTION READ ONLY' in q and 'IS_FREE_LOCK' in q and 'GET_LOCK(' not in q
assert not re.search(r'\b(?:INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)\b',q)
assert "set_transient('cdta_periods_v1'" in q and 'revision' in q and 'LIMIT %d OFFSET %d' in q
css=(r/'wp-content/themes/cyberdat/assets/css/threat-analytics.css').read_text();assert 'site-main' not in css and '.container' not in css
js=(r/'wp-content/themes/cyberdat/assets/js/threat-analytics.js').read_text();assert 'innerHTML' not in js and 'endpoint.origin!==location.origin' in js and 'AbortController' in js
print('PASS: backup-before-install, bounded read-only SQL, separate cache, same-origin data, no Research/timer or global-width changes')
