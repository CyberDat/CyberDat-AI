/*
 * Hub card previews (assets/images/tools-hub/<slug>.svg): every catalogue entry has one, each is a static,
 * self-contained decorative SVG in the shared 480x260 frame, and its visible text is synthetic (reserved
 * example domains, DEMO_ / CANARY- markers, documentation IP ranges only). The Hub template wires them by
 * catalogue slug, so no catalogue field is needed. Run: node tests/tools-hub-previews.test.cjs
 */
'use strict';
const fs = require('fs');
const path = require('path');
const THEME = path.join(__dirname, '../wp-content/themes/cyberdat');
const DIR = path.join(THEME, 'assets/images/tools-hub');
const catalog = JSON.parse(fs.readFileSync(path.join(THEME, 'inc/tools-catalog.json'), 'utf8'));
const tpl = fs.readFileSync(path.join(THEME, 'page-templates/tools.php'), 'utf8');
let failed = 0;
const check = (ok, msg) => { console.log((ok ? 'PASS: ' : 'FAIL: ') + msg); if (!ok) { failed++; } };

// Template wiring (read only): slug-named file, empty alt, aria-hidden, explicit size.
check(tpl.includes("'/assets/images/tools-hub/' . basename( $tool['slug'] ) . '.svg'"), 'template maps each catalogue slug to its preview file');
check(/<img src="[^"]*" width="480" height="260" alt="" aria-hidden="true"/u.test(tpl), 'previews are rendered decorative: alt="", aria-hidden, 480x260');

const NEW = ['agent-leak-inspector', 'ai-model-bom', 'mitre-atlas-mapper', 'prompt-injection-test-bench', 'yara-sigma-validator', 'container-hardening-audit', 'email-header-analyzer'];
const texts = s => [...s.matchAll(/<text\b[^>]*>([^<]*)<\/text>/gu)].map(m => m[1].replace(/&lt;/gu, '<').replace(/&gt;/gu, '>').replace(/&amp;/gu, '&'));
for (const tool of catalog) {
	const f = path.join(DIR, tool.slug + '.svg');
	check(fs.existsSync(f), tool.slug + ': preview file exists');
	if (!fs.existsSync(f)) { continue; }
	const s = fs.readFileSync(f, 'utf8');
	check(s.startsWith('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 480 260"'), tool.slug + ': shared 480x260 frame');
	check(Buffer.byteLength(s) <= 4096, tool.slug + ': at most 4 KB (' + Buffer.byteLength(s) + ' bytes)');
	check(!/<script|<foreignObject|<image\b|<use\b|<a\b|<style|\son[a-z]+\s*=|href\s*=|@import|url\((?!#)/iu.test(s), tool.slug + ': no script, external reference, link, style block or event handler');
	check(!/<animate|<set\b/iu.test(s), tool.slug + ': no animation');
	const ids = [...s.matchAll(/\bid="([^"]+)"/gu)].map(m => m[1]);
	check(ids.length === new Set(ids).size, tool.slug + ': unique ids');
	if (!NEW.includes(tool.slug)) { continue; }
	// New previews: window with three dots, an input and a result, synthetic text only.
	check((s.match(/<circle cx="(?:47|59|71)" cy="49" r="3"/gu) || []).length === 3, tool.slug + ': window with three dots');
	const t = texts(s);
	check(t.length === 6, tool.slug + ': title, two input lines, two result lines and footer');
	const all = t.join('\n');
	const domains = [...all.matchAll(/\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|de|ru|eu)\b/gu)].map(m => m[0]);
	check(domains.every(d => /(?:^|\.)example\.(?:com|net|org)$/u.test(d)), tool.slug + ': domains are reserved examples only (' + (domains.join(', ') || 'none') + ')');
	const ips = all.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/gu) || [];
	check(ips.every(ip => /^(?:192\.0\.2|198\.51\.100|203\.0\.113)\./u.test(ip)), tool.slug + ': IP addresses only from documentation ranges');
	check(!/@(?!example\.(?:com|net|org)\b)/u.test(all), tool.slug + ': e-mail addresses only at example domains');
	check(!/[A-Za-z0-9+/_-]{20,}/u.test(all), tool.slug + ': no long token-shaped run in the visible text');
	check(!/\b(?:sk|pk|ghp|gho|xox[abp]|AKIA|AIza|eyJ)[-_A-Za-z0-9]/u.test(all), tool.slug + ': no credential prefixes');
	const users = all.match(/\b[A-Z][A-Z0-9]*_[A-Z0-9_]+\b/gu) || [];
	check(users.every(u => u.startsWith('DEMO_')), tool.slug + ': placeholder names use DEMO_');
	const canaries = all.match(/CANARY[-\w]*/gu) || [];
	check(canaries.every(c => /^CANARY-\d{4}$/u.test(c)), tool.slug + ': canary markers are CANARY-<4 digits>');
}
check(catalog.length === 11, 'eleven catalogue entries checked');
console.log(failed ? failed + ' check(s) failed' : 'PASS: Hub card previews');
process.exit(failed ? 1 : 0);
