#!/usr/bin/env python3
"""Temporary loopback-only Tools renderer; never serves WordPress or staging."""
import argparse
import http.server
import json
import mimetypes
from pathlib import Path
import subprocess
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / 'wp-content/themes/cyberdat/assets'
SLUGS = ['log-anonymizer', 'prompt-injection-detector', 'lotl-command-analyzer', 'mcp-security-checker', 'agent-leak-inspector']
PAGES = {}
for slug in SLUGS:
    r = subprocess.run(['/usr/bin/php8.4', str(ROOT / 'tests/tools-sandbox-render.php'), slug], capture_output=True, text=True)
    if r.returncode or r.stderr: raise RuntimeError('sandbox renderer failed: ' + slug + ': ' + r.stderr[:300])
    PAGES['/tools/' + slug + '/'] = json.loads(r.stdout)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        path = urlsplit(self.path).path
        if path == '/favicon.ico':
            self.send_response(204); self.end_headers(); return
        if path in PAGES:
            page = PAGES[path]; b = page['html'].encode()
            self.send_response(200); self.send_header('Content-Type', 'text/html; charset=utf-8')
            for line in page['headers']:
                name, value = line.split(':', 1); self.send_header(name, value.strip())
        elif path.startswith('/wp-content/themes/cyberdat/assets/'):
            p = (ASSETS / path.split('/assets/', 1)[1]).resolve()
            if not p.is_relative_to(ASSETS) or not p.is_file(): self.send_error(404); return
            b = p.read_bytes(); self.send_response(200); self.send_header('Content-Type', mimetypes.guess_type(p)[0] or 'application/octet-stream')
        else: self.send_error(404); return
        self.send_header('Cache-Control', 'no-store');self.send_header('Content-Length', str(len(b)));self.end_headers();self.wfile.write(b)


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('--port', type=int, default=18090); a = p.parse_args()
    server = http.server.ThreadingHTTPServer(('127.0.0.1', a.port), Handler)
    print('SANDBOX http://127.0.0.1:' + str(server.server_port) + ' (no WordPress/SQL)', flush=True)
    server.serve_forever()
