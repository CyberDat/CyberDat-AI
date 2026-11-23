/*
 * Warning before large inputs — the shared block in the nine tools that accept files (round 11, 2026-11-23):
 *  - the block is identical in every copy, and every tool calls it when a file is chosen and when processing starts;
 *  - thresholds 10 MB, and 5 MB in Safari and other WebKit-based browsers; the message names the size, a rough time and Cancel;
 *  - the size limits of the tools are unchanged (compared with the staging theme 73d99a4).
 * The browser behaviour (progress, Cancel, identical results) is tested in tests/tools-large-input-xbrowser.test.cjs.
 *   node tests/tools-large-input-block.test.cjs
 */
'use strict';
const cp = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ROOT = path.join(__dirname, '..');
const J = 'wp-content/themes/cyberdat/assets/js/';
const TOOLS = ['log-anonymizer', 'prompt-injection-detector', 'lotl-analyzer', 'mcp-checker', 'leak-inspector', 'ai-model-bom', 'email-header-analyzer', 'container-hardening-audit', 'prompt-injection-test-bench'];
let failed = 0, n = 0;
const check = (ok, msg) => { n++; console.log((ok ? 'PASS: ' : 'FAIL: ') + msg); if (!ok) { failed++; } };
const A = '// ---------------------------------------------------------------- warning before large inputs (shared block)';
const B = '// ---------------------------------------------------------------- end of warning before large inputs (shared block)';
const src = t => fs.readFileSync(path.join(ROOT, J, t, 'app.js'), 'utf8').replace(/\r\n/g, '\n');
const block = s => { const a = s.indexOf(A), b = s.indexOf(B); return a > 0 && b > a ? s.slice(a, b + B.length) : ''; };
const blocks = TOOLS.map(t => block(src(t)));
check(blocks.every(Boolean) && blocks.every(b => b === blocks[0]), 'the block is present and identical in all ' + TOOLS.length + ' tools');
for (const t of TOOLS) {
	const s = src(t);
	const calls = (s.match(/\blargeInput\(/g) || []).length;
	const afterRun = /setRunning\(true\);\n(?:[^\n]*\n)?\t\tlargeInput\(/.test(s);
	check(calls === 3 && afterRun && /function largeInput\(bytes\) \{ return largeUpdate\(el\.progress, bytes, LARGE_INPUT_RATE\); \}/.test(s), t + ': warns when a file is chosen and when processing starts (after the progress bar)');
	check(!/CyberDatLargeInput|fetch\(|XMLHttpRequest|localStorage|sessionStorage|eval\(/.test(block(s)), t + ': the block uses no global object, network, storage or eval');
}
// behaviour of the block with a minimal DOM, as Edge and as WebKit
function load(ua) {
	const nodes = [];
	const el = () => ({ attrs: {}, hidden: false, textContent: '', className: '', setAttribute(k, v) { this.attrs[k] = v; }, hasAttribute(k) { return k in this.attrs; }, get nextElementSibling() { return nodes[nodes.indexOf(this) + 1] || null; }, parentNode: null });
	const parent = { insertBefore(node, before) { const i = before ? nodes.indexOf(before) : nodes.length; nodes.splice(i < 0 ? nodes.length : i, 0, node); node.parentNode = parent; } };
	const anchor = el(); anchor.parentNode = parent; nodes.push(anchor);
	const ctx = { window: { navigator: { userAgent: ua, maxTouchPoints: 0 } }, document: { createElement: () => el() }, Math, Number, String };
	vm.runInNewContext(blocks[0] + '\nthis.api = { largeUpdate, largeEstimate, LARGE_THRESHOLD, LARGE_WEBKIT };', ctx);
	return { api: ctx.api, anchor, box: () => anchor.nextElementSibling };
}
const MB = 1024 * 1024;
const EDGE = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0';
const SAFARI = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15';
const IPHONE_CHROME = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0 Mobile/15E148 Safari/604.1';
const FIREFOX = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0';
for (const [name, ua, webkit] of [['Edge', EDGE, false], ['Firefox', FIREFOX, false], ['Safari', SAFARI, true], ['Chrome on iPhone', IPHONE_CHROME, true]]) {
	const x = load(ua);
	check(x.api.LARGE_WEBKIT === webkit && x.api.LARGE_THRESHOLD === (webkit ? 5 : 10) * MB, name + ': threshold ' + (webkit ? '5' : '10') + ' MB');
	check(x.api.largeUpdate(x.anchor, x.api.LARGE_THRESHOLD, null) === false && x.box().hidden, name + ': no warning at the threshold itself');
	check(x.api.largeUpdate(x.anchor, 12 * MB, { fast: 6.3, fastSlow: 2.5, webkit: 1.0 }) && !x.box().hidden && /^Large input: 12\.0 MB\. Processing in this browser can take about /.test(x.box().textContent) && /Cancel stops the processing/.test(x.box().textContent) && /WebKit-based browsers/.test(x.box().textContent) === webkit && x.box().attrs.role === 'status', name + ': 12 MB warns with size, time and Cancel' + (webkit ? ' and the WebKit note' : ''));
	check(x.api.largeUpdate(x.anchor, 0) === false && x.box().hidden && x.box().textContent === '', name + ': the warning is removed for a small input');
}
{
	const safari = load(SAFARI).api.largeEstimate(30 * MB, { fast: 6.3, fastSlow: 2.5, webkit: 1.0 });
	check(safari[0] <= 27 * 1.2 && safari[1] >= 122, 'Log Anonymizer, 30 MB in WebKit: estimate ' + safari.join('–') + ' s covers the 27–122 s Codex measured');
	const edge = load(EDGE).api.largeEstimate(30 * MB, { fast: 6.3, fastSlow: 2.5, webkit: 1.0 });
	check(edge[0] <= 5 && edge[1] >= 12, 'Log Anonymizer, 30 MB in Edge/Firefox: estimate ' + edge.join('–') + ' s covers about 4.7 s (Edge) and 11.8 s (Firefox), extrapolated from the 12 MB runs');
}
// size limits unchanged since the staging theme
const LIMITS = { 'log-anonymizer': /const MAX_BYTES = [^;]+;/, 'prompt-injection-detector': /const MAX_BYTES = [^;]+;/, 'lotl-analyzer': /const MAX_BYTES = [^;]+;/, 'mcp-checker': /const MAX_BYTES = [^;]+;/, 'leak-inspector': /const MAX_RESPONSE = [^;]+;/, 'ai-model-bom': /const MAX_BYTES = [^;]+;/, 'email-header-analyzer': /const MAX_CHARS = [^;]+;/, 'container-hardening-audit': /const MAX_CHARS = [^;]+;/, 'prompt-injection-test-bench': /const MAX_TOTAL = [^;]+;/ };
let base = null;
try { cp.execSync('git cat-file -e 73d99a4^{commit}', { cwd: ROOT, stdio: 'ignore' }); base = '73d99a4'; } catch (e) { base = null; }
for (const t of TOOLS) {
	const now = (src(t).match(LIMITS[t]) || [''])[0];
	const before = base ? (cp.execSync('git show ' + base + ':' + J + t + '/app.js', { cwd: ROOT }).toString('utf8').match(LIMITS[t]) || [''])[0] : now;
	check(now && now === before, t + ': size limit unchanged (' + now + ')' + (base ? '' : ' — staging commit not in this clone, compared with itself'));
}
console.log(failed ? 'FAIL: ' + failed + ' of ' + n + ' checks' : '\nPASS: warning before large inputs, shared block (' + n + ' checks)');
process.exitCode = failed ? 1 : 0;
