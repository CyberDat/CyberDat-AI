/*
 * Hub card previews, grouped by the package that ships them. Writes
 *   deploy/tools-hub-previews-5-7/previews.json   tools 5-7 (installed on staging) + the illustrations README, for Codex
 *   deploy/tools-release-1.3/hub-previews.json    tools 8-10, part of the release 1.3 package
 * The Email Header Analyzer preview is in deploy/tools-utilities-1/manifest.json (tools.email-header-analyzer.hub_preview).
 * base_sha256 = the file in the Codex Hub on staging (feat/tools-hub-cyber-glass 0a32f12). Hashes are of the LF bytes in git.
 * The Hub template is not changed by these files: it picks assets/images/tools-hub/<catalogue slug>.svg.
 *   node deploy/tools-hub-previews-5-7/build-previews.cjs [themeCommit] [--check]
 */
'use strict';
const cp = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const HUB_COMMIT = '0a32f1234e596c425cda58b096ea1e085147386f';
const THEME = 'wp-content/themes/cyberdat/';
const DIR = 'assets/images/tools-hub/';
const ROOT = path.join(__dirname, '../..');
const sh = c => cp.execSync(c, { cwd: ROOT, maxBuffer: 1 << 26 });
const CHECK = process.argv.includes('--check');
const commit = sh('git rev-parse ' + (process.argv.slice(2).find(x => !x.startsWith('--')) || 'HEAD')).toString().trim();
const info = (rev, p) => { const b = sh('git cat-file blob ' + rev + ':' + THEME + p); return { bytes: b.length, sha256: crypto.createHash('sha256').update(b).digest('hex') }; };
const GROUPS = {
	'deploy/tools-hub-previews-5-7/previews.json': { package: 'tools-hub-previews-5-7', tools: [[5, 'agent-leak-inspector'], [6, 'ai-model-bom'], [7, 'mitre-atlas-mapper']], extra: [DIR + 'README.md'] },
	'deploy/tools-release-1.3/hub-previews.json': { package: 'tools-release-1.3 (hub previews)', tools: [[8, 'prompt-injection-test-bench'], [9, 'yara-sigma-validator'], [10, 'container-hardening-audit']], extra: [] }
};
let ok = true;
for (const [out, g] of Object.entries(GROUPS)) {
	const files = {};
	for (const [n, slug] of g.tools) { const p = DIR + slug + '.svg'; files[p] = Object.assign({ tool: n, slug, status: 'modified' }, info(commit, p), { base_sha256: info(HUB_COMMIT, p).sha256 }); }
	for (const p of g.extra) { files[p] = Object.assign({ status: 'modified', note: 'illustrations README: sizes and the synthetic-text rule for the new previews' }, info(commit, p), { base_sha256: info(HUB_COMMIT, p).sha256 }); }
	const doc = {
		schema: 'cyberdat-hub-previews/1', package: g.package, theme_commit: commit, hub_commit: HUB_COMMIT,
		note: 'Replace these files in the installed Hub (paths relative to the theme). Decorative 480x260 SVGs, synthetic text only, no scripts or external references; the Hub template and the catalogue are unchanged (the template picks the file by catalogue slug, with alt="" and aria-hidden). Verify base_sha256 on staging before replacing and sha256 after.',
		files
	};
	const file = path.join(ROOT, out);
	const text = JSON.stringify(doc, null, 2) + '\n';
	if (CHECK) {
		const cur = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : null;
		const same = cur && JSON.stringify(cur.files) === JSON.stringify(files);
		console.log((same ? 'PASS: ' : 'FAIL: ') + out + ' at ' + commit.slice(0, 12));
		ok = ok && same;
	} else {
		fs.writeFileSync(file, text);
		console.log(out + ': ' + Object.keys(files).length + ' files');
	}
}
process.exit(ok ? 0 : 1);
