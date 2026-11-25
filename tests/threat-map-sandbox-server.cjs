/*
 * Loopback-only static server for the threat map stand: /stand/<scenario>/ → the page rendered by
 * tests/threat-map-sandbox.php into <pages-dir>, /wp-content/themes/cyberdat/assets/* → theme files.
 *   node tests/threat-map-sandbox-server.cjs <pages-dir> [port]
 */
'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const PAGES = path.resolve(process.argv[2] || '');
const PORT = Number(process.argv[3] || 18093);
const ASSETS = path.resolve(__dirname, '..', 'wp-content', 'themes', 'cyberdat', 'assets');
const TYPES = { '.css': 'text/css', '.js': 'text/javascript', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2' };
if (!fs.existsSync(PAGES)) { console.error('pages dir missing'); process.exit(2); }
http.createServer((req, res) => {
	const url = new URL(req.url, 'http://127.0.0.1');
	const send = (code, type, body) => { res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store', 'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; script-src 'self'" }); res.end(body); };
	if (url.pathname === '/favicon.ico') { res.writeHead(204); return res.end(); }
	let m = url.pathname.match(/^\/stand\/([a-z]+)\/$/);
	if (m) {
		const file = path.join(PAGES, m[1] + '.html');
		return fs.existsSync(file) ? send(200, 'text/html; charset=utf-8', fs.readFileSync(file)) : send(404, 'text/plain', 'no such scenario');
	}
	m = url.pathname.match(/^\/wp-content\/themes\/cyberdat\/assets\/(.+)$/);
	if (m) {
		const file = path.resolve(ASSETS, decodeURIComponent(m[1]));
		if (!file.startsWith(ASSETS + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) return send(404, 'text/plain', 'not found');
		return send(200, TYPES[path.extname(file)] || 'application/octet-stream', fs.readFileSync(file));
	}
	send(404, 'text/plain', 'not found');
}).listen(PORT, '127.0.0.1', () => console.log('THREAT MAP STAND http://127.0.0.1:' + PORT + '/stand/data/'));
