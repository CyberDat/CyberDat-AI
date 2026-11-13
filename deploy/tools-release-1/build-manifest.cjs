/*
 * Builds deploy/tools-release-1/manifest.json: every theme file that differs between the Research 0.8.3 base and the
 * integration commit, with git blob ids, SHA-256 of the exact LF bytes stored in git, sizes, and the base SHA-256 for
 * modified files (added files must be absent before deployment).
 *   node deploy/tools-release-1/build-manifest.cjs [themeCommit]
 */
'use strict';
const cp = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const BASE = 'c3f9a5e7172f83006f3b078705a9d89e709619f8';
const THEME = 'wp-content/themes/cyberdat/';
const sh = c => cp.execSync(c, { maxBuffer: 1 << 28 });
const commit = sh('git rev-parse ' + (process.argv[2] || 'HEAD')).toString().trim();
const sha = buf => crypto.createHash('sha256').update(buf).digest('hex');
const rows = sh('git diff --name-status ' + BASE + ' ' + commit + ' -- ' + THEME).toString().trim().split('\n').map(l => l.split('\t')).sort((a, b) => a[1].localeCompare(b[1]));
const files = {};
for (const [status, p] of rows) {
	if (status === 'D') { files[p.slice(THEME.length)] = { status: 'deleted', base_sha256: sha(sh('git show ' + BASE + ':' + p)) }; continue; }
	const buf = sh('git show ' + commit + ':' + p);
	const e = { status: status === 'A' ? 'added' : 'modified', tool: toolOf(p), git_blob_sha1: sh('git rev-parse ' + commit + ':' + p).toString().trim(), sha256: sha(buf), bytes: buf.length };
	if (status !== 'A') { e.base_sha256 = sha(sh('git show ' + BASE + ':' + p)); }
	files[p.slice(THEME.length)] = e;
}
function toolOf(p) {
	if (/log-anonymizer/.test(p)) { return 'log-anonymizer'; }
	if (/prompt-injection-detector/.test(p)) { return 'prompt-injection-detector'; }
	if (/lotl/.test(p)) { return 'lotl-command-analyzer'; }
	if (/mcp-/.test(p)) { return 'mcp-security-checker'; }
	return 'shared';
}
const manifest = {
	release: 'CyberDat Tools release 1 bundle: Log Anonymizer, Prompt Injection Detector, LotL / LOLBAS Command Analyzer (release 1.1) and MCP Security & Policy Checker (release 1.2)',
	repository: 'CyberDat/CyberDat-AI',
	branch: 'integration/tools-release-1',
	theme_commit: commit,
	base_commit: BASE,
	base_description: 'feat/cyberdat-research-agent-0.8.3 tip; base_sha256 values are the files at this commit',
	requires_owner_approval_before_deploy: true,
	hashes: 'sha256 of the file bytes as stored in git (LF line endings). Export with: git -c core.autocrlf=false archive <theme_commit> wp-content/themes/cyberdat',
	theme_directory: 'wp-content/themes/cyberdat',
	supersedes: ['deploy/tools-log-anonymizer/manifest.json', 'deploy/tools-prompt-injection-detector/manifest.json', 'deploy/tools-lotl-analyzer/manifest.json', 'deploy/tools-mcp-checker/manifest.json'],
	file_count: Object.keys(files).length,
	files
};
fs.writeFileSync(path.join(__dirname, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log('manifest: ' + manifest.file_count + ' files at ' + commit.slice(0, 12) + ' (' + Object.values(files).filter(f => f.status === 'modified').length + ' modified, ' + Object.values(files).filter(f => f.status === 'added').length + ' added)');
