import http.server,subprocess,urllib.parse,json,hashlib,re,argparse
from html.parser import HTMLParser
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--baseline-html',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--wordpress-public',type=Path);p.add_argument('--baseline-filter',type=Path,required=True);p.add_argument('--port',type=int,default=18115);a=p.parse_args();D=a.output.resolve();D.mkdir(parents=True,exist_ok=True);W=Path(__file__).resolve().parents[1];THEME=W/'wp-content/themes/cyberdat';PORT=a.port
raw=a.baseline_html.read_text()
class Locate(HTMLParser):
 def __init__(self,s):super().__init__();self.s=s;self.lines=s.splitlines(keepends=True);self.start=None;self.end=None;self.depth=0
 def position(self):line,col=self.getpos();return sum(map(len,self.lines[:line-1]))+col
 def handle_starttag(self,tag,attrs):
  if tag=='article':
   if self.start is None and 'cyberdat-catalog' in dict(attrs).get('class',''):self.start=self.position();self.depth=1
   elif self.start is not None and self.end is None:self.depth+=1
 def handle_endtag(self,tag):
  if tag=='article' and self.start is not None and self.end is None:
   self.depth-=1
   if self.depth==0:self.end=self.position()+len('</article>')
l=Locate(raw);l.feed(raw);assert l.start is not None and l.end is not None
prefix=raw[:l.start];suffix=raw[l.end:]
def local_assets(s):
 s=s.replace('"concatemoji":"https://staging.cyberdat.eu/wp-includes/', '"concatemoji":"/wp-includes/')
 s=s.replace('https:\\/\\/staging.cyberdat.eu\\/wp-includes\\/js\\/wp-emoji-release.min.js','\\/wp-includes\\/js\\/wp-emoji-release.min.js')
 return re.sub(r'((?:src|href)=["\'])https://staging\.cyberdat\.eu(/(?:wp-content|wp-includes)/)',r'\1\2',s)
def document(mode):
 if mode=='before':
  out=local_assets(raw);return out.replace('/assets/js/tools-filter.js?','/assets/js/tools-filter.js?baseline=1&')
 p=subprocess.run(['/usr/bin/php8.4','-n',str(W/'tests/tools-hub-render.php'),mode],text=True,capture_output=True,timeout=10);assert p.returncode==0 and not p.stderr,p.stderr
 head=prefix.replace('</head>','<link rel="stylesheet" href="/wp-content/themes/cyberdat/assets/css/tools-hub.css"></head>')
 fragment=p.stdout
 old_related=re.search(r'<nav class="cyberdat-tool-related".*?</nav>',raw,re.S)
 if mode=='current' and old_related:fragment=re.sub(r'<nav class="cyberdat-tool-related".*?</nav>',lambda m:old_related.group(),fragment,flags=re.S)
 return local_assets(head+fragment+suffix)
for mode in ['before','current','future','none']:(D/(mode+'.html')).write_text(document(mode))
class Handler(http.server.SimpleHTTPRequestHandler):
 def do_GET(self):
  u=urllib.parse.urlparse(self.path);path=u.path
  if path in ['/before/','/after/','/future/','/none/']:
   name={'/before/':'before','/after/':'current','/future/':'future','/none/':'none'}[path];body=(D/(name+'.html')).read_bytes();typ='text/html; charset=utf-8'
  elif path.startswith('/wp-content/themes/cyberdat/'):
   rel=path.removeprefix('/wp-content/themes/cyberdat/');p=THEME/rel
   if '..' in Path(rel).parts or not p.is_file():self.send_error(404);return
   if 'baseline=1' in u.query and rel=='assets/js/tools-filter.js':
    p=a.baseline_filter

   body=p.read_bytes();typ=self.guess_type(str(p))
  elif a.wordpress_public and path.startswith('/wp-includes/') and path.endswith(('.css','.js','.svg','.png')):
   p=a.wordpress_public/path.lstrip('/')
   if '..' in Path(path).parts or not p.is_file():self.send_error(404);return
   body=p.read_bytes();typ=self.guess_type(str(p))
  elif path=='/favicon.ico':body=b'';typ='image/x-icon'
  else:self.send_error(404);return
  self.send_response(200);self.send_header('Content-Type',typ);self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store');self.end_headers();self.wfile.write(body)
 def do_HEAD(self):self.send_error(405)
 def log_message(self,*a):pass
print('Isolated static/PHP-double preview on loopback:'+str(PORT)+'; no WordPress/SQL execution',flush=True)
http.server.ThreadingHTTPServer(('127.0.0.1',PORT),Handler).serve_forever()
