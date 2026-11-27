/*
 * AI tools: OWASP references follow the 2026 editions (OWASP Top 10 for LLM Applications 2026, OWASP Top 10 for
 * Agentic Applications 2026). No LLMxx:2025 IDs and no old "System Prompt Leakage" title in user-facing texts (the
 * 2025 → 2026 table in docs/OWASP-2026-MAPPING.md is the only exception); the IDs and titles in the theme equal
 * the official tables in that document; every AI tool page shows the mapping line and the rules update date.
 *   node tests/ai-tools-owasp-2026.test.cjs
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ROOT = path.join(__dirname, '..');
const THEME = path.join(ROOT, 'wp-content', 'themes', 'cyberdat');
const read = p => fs.readFileSync(p, 'utf8').replace(/\r\n/g, '\n');
let n = 0;
const pass = l => { n++; console.log('PASS: ' + l); };

// user-facing texts: the theme (templates, inc, scripts, catalogue) and the editorial JSON of the packages
const files = [];
const walk = d => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (/\.(php|js|json|html|md|txt)$/.test(e.name)) files.push(p); } };
walk(THEME);
for (const d of fs.readdirSync(path.join(ROOT, 'deploy'))) { const dir = path.join(ROOT, 'deploy', d); if (fs.statSync(dir).isDirectory()) for (const f of fs.readdirSync(dir)) if (/^editorial.*\.json$/.test(f)) files.push(path.join(dir, f)); }
const bad = files.filter(f => !/email-header-analyzer[\\/]psl-data\.js$/.test(f)).flatMap(f => { const t = read(f); return [...t.matchAll(/LLM\d{2}:2025|System Prompt Leakage/g)].map(m => path.relative(ROOT, f) + ': ' + m[0]); });
assert.deepEqual(bad, []);
pass(`no LLMxx:2025 ID and no "System Prompt Leakage" in ${files.length} user-facing theme and editorial files`);

const inc = read(path.join(THEME, 'inc', 'tools-owasp-2026.php'));
const doc = read(path.join(ROOT, 'docs', 'OWASP-2026-MAPPING.md'));
const php = name => Object.fromEntries([...inc.split('const ' + name + ' = array(')[1].split(');')[0].matchAll(/'([^']+)' => '([^']+)'/g)].map(m => [m[1], m[2]]));
const llm = php('CYBERDAT_OWASP_LLM_2026'), asi = php('CYBERDAT_OWASP_ASI_2026');
const docTable = re => Object.fromEntries([...doc.matchAll(re)].map(m => [m[1], m[2]]));
const docLlm = docTable(/^\| (LLM\d{2}:2026) \| ([^|]+?) \| `LLM\d{2}_/gm), docAsi = docTable(/^\| (ASI\d{2}) \| ([^|]+?) \|$/gm);
assert.equal(Object.keys(llm).length, 10);
assert.equal(Object.keys(asi).length, 10);
assert.deepEqual(llm, docLlm);
assert.deepEqual(asi, docAsi);
assert.deepEqual(Object.keys(llm), Array.from({ length: 10 }, (_, i) => 'LLM' + String(i + 1).padStart(2, '0') + ':2026'));
assert.equal(llm['LLM08:2026'], 'Hidden Context Exposure');
assert.match(doc, /\| LLM07:2025 System Prompt Leakage \| LLM08:2026 Hidden Context Exposure \|/);
pass('theme IDs and titles = the official LLM 2026 and Agentic 2026 tables in docs/OWASP-2026-MAPPING.md (10 + 10)');

const pages = { 'prompt-injection-detector': ['LLM01:2026'], 'prompt-injection-test-bench': ['LLM01:2026'], 'agent-leak-inspector': ['LLM08:2026', 'LLM02:2026', 'LLM03:2026'], 'mcp-security-checker': ['LLM03:2026', 'LLM04:2026'], 'mitre-atlas-mapper': [], 'ai-model-bom': ['LLM04:2026'] };
for (const [slug, ids] of Object.entries(pages)) {
	const t = read(path.join(THEME, 'template-parts', 'tools', slug + '.php'));
	assert.ok(t.includes("require_once dirname( __DIR__, 2 ) . '/inc/tools-owasp-2026.php';"), slug);
	assert.ok(t.includes("cyberdat_tools_owasp_line( '" + slug + "' )"), slug);
	assert.match(t, / updated %\d\$s', 'cyberdat' \),[^\n]*cyberdat_rules_updated\(/, slug);
	const map = inc.match(new RegExp("'" + slug + "'\\s*=> array\\( array\\(([^)]*)\\)"));
	if (ids.length) assert.deepEqual([...map[1].matchAll(/'(LLM\d{2}:2026)'/g)].map(m => m[1]), ids, slug);
}
assert.ok(read(path.join(THEME, 'template-parts', 'tools', 'agent-leak-inspector.php')).includes('entry LLM08:2026 “Hidden Context Exposure”'));
assert.ok(!/<a\s/i.test(inc), 'tool pages name sources without links');
pass('six AI tool pages: OWASP 2026 line (names only, no links), "rules updated <date>" from the ruleset ID; Leak Inspector cites LLM08:2026');
console.log(`PASS: AI tools OWASP 2026 — ${n} groups`);
