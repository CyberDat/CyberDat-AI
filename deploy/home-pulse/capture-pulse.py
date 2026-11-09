#!/usr/bin/env python3
"""Windows 11 / existing Edge only. Hidden staging Basic Auth, isolated temporary profile.
No packages installed. Saves screenshots and a sanitized layout/console report locally.
"""
import base64,getpass,hashlib,http.client,json,os,pathlib,secrets,shutil,socket,struct,subprocess,sys,tempfile,time,urllib.parse,urllib.request
P=pathlib.Path;HOST='https://staging.cyberdat.eu'
def need(ok,message):
 if not ok:raise RuntimeError(message)
class DevTools:
 def __init__(self,url,authorization):
  p=urllib.parse.urlsplit(url);need(p.scheme=='ws' and p.hostname=='127.0.0.1','Nonlocal DevTools rejected');self.s=socket.create_connection(('127.0.0.1',p.port),timeout=30);self.buffer=b'';self.id=0;self.authorization=authorization;self.console_errors=0;self.runtime_errors=0
  key=base64.b64encode(secrets.token_bytes(16)).decode();request=('GET '+p.path+' HTTP/1.1\r\nHost: 127.0.0.1:'+str(p.port)+'\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: '+key+'\r\nSec-WebSocket-Version: 13\r\n\r\n').encode();self.s.sendall(request)
  while b'\r\n\r\n' not in self.buffer:
   chunk=self.s.recv(4096);need(bool(chunk),'DevTools handshake connection closed');self.buffer+=chunk
  header,self.buffer=self.buffer.split(b'\r\n\r\n',1);accept=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest());need(b' 101 ' in header and accept.lower() in header.lower(),'DevTools handshake failed')
 def read(self,n):
  while len(self.buffer)<n:
   chunk=self.s.recv(max(4096,n-len(self.buffer)));need(bool(chunk),'DevTools connection closed');self.buffer+=chunk
  out,self.buffer=self.buffer[:n],self.buffer[n:];return out
 def send(self,obj):
  data=json.dumps(obj).encode();mask=secrets.token_bytes(4);size=len(data);head=bytes([0x81,0x80|(size if size<126 else 126 if size<65536 else 127)])+(b'' if size<126 else struct.pack('!H' if size<65536 else '!Q',size));self.s.sendall(head+mask+bytes(v^mask[i%4] for i,v in enumerate(data)))
 def receive(self):
  parts=[]
  while True:
   h=self.read(2);op=h[0]&15;size=h[1]&127
   if size==126:size=struct.unpack('!H',self.read(2))[0]
   elif size==127:size=struct.unpack('!Q',self.read(8))[0]
   need(size<=32*1024*1024,'DevTools frame too large');mask=self.read(4) if h[1]&128 else None;data=self.read(size)
   if mask:data=bytes(v^mask[i%4] for i,v in enumerate(data))
   need(op!=8,'DevTools closed')
   if op in (1,0):parts.append(data)
   if h[0]&128 and op in (1,0):return json.loads(b''.join(parts))
 def command(self,method,params=None):
  self.id+=1;identity=self.id;self.send({'id':identity,'method':method,'params':params or {}})
  while True:
   response=self.receive()
   if response.get('id')==identity:need('error' not in response,'DevTools operation failed: '+method);return response.get('result',{})
   self.event(response)
 def event(self,event):
  name=event.get('method');p=event.get('params',{})
  if name=='Fetch.requestPaused':
   request=p['request'];u=urllib.parse.urlsplit(request['url']);allowed=u.scheme=='https' and u.netloc=='staging.cyberdat.eu'
   self.id+=1
   if allowed:
    headers=[{'name':k,'value':v} for k,v in request.get('headers',{}).items() if k.lower()!='authorization'];headers.append({'name':'Authorization','value':self.authorization});self.send({'id':self.id,'method':'Fetch.continueRequest','params':{'requestId':p['requestId'],'headers':headers}})
   else:self.send({'id':self.id,'method':'Fetch.failRequest','params':{'requestId':p['requestId'],'errorReason':'BlockedByClient'}})
  elif name=='Fetch.authRequired':
   self.id+=1;self.send({'id':self.id,'method':'Fetch.continueWithAuth','params':{'requestId':p['requestId'],'authChallengeResponse':{'response':'CancelAuth'}}})
  elif name=='Runtime.exceptionThrown':self.runtime_errors+=1
  elif name=='Log.entryAdded' and p.get('entry',{}).get('level')=='error':self.console_errors+=1
 def evaluate(self,code):return self.command('Runtime.evaluate',{'expression':code,'returnByValue':True})['result'].get('value')
 def close(self):self.s.close()
def main():
 need(os.name=='nt','Run on Windows 11; this script does not install a browser on the VPS')
 candidates=[P(os.environ.get('PROGRAMFILES(X86)','C:/Program Files (x86)'))/'Microsoft/Edge/Application/msedge.exe',P(os.environ.get('PROGRAMFILES','C:/Program Files'))/'Microsoft/Edge/Application/msedge.exe'];browser=next((p for p in candidates if p.is_file()),None);need(browser is not None,'Existing Microsoft Edge not found')
 password=getpass.getpass('EXISTING staging HTTP Basic Auth password (hidden): ');need(bool(password),'Basic Auth required');authorization='Basic '+base64.b64encode(('cyberdat_staging_admin:'+password).encode()).decode()
 stamp=time.strftime('%Y%m%dT%H%M%SZ',time.gmtime());output=P.home()/('CyberDat-home-pulse-screenshots-'+stamp);output.mkdir(exist_ok=False)
 profile=tempfile.mkdtemp(prefix='cyberdat-dashboard-edge-');probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close();process=None;cdp=None
 try:
  process=subprocess.Popen([str(browser),'--headless=new','--disable-gpu','--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-component-update','--disable-sync','--disable-extensions','--remote-debugging-address=127.0.0.1','--remote-debugging-port='+str(port),'--user-data-dir='+profile,'about:blank'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  opener=urllib.request.build_opener(urllib.request.ProxyHandler({}));deadline=time.monotonic()+30;target=None
  while time.monotonic()<deadline:
   try:
    with opener.open('http://127.0.0.1:'+str(port)+'/json/list',timeout=2) as response:tabs=json.load(response)
    target=next((t for t in tabs if t.get('type')=='page'),None)
    if target:break
   except (OSError,ValueError):pass
   time.sleep(.25)
  need(target is not None,'Isolated Edge DevTools not ready');cdp=DevTools(target['webSocketDebuggerUrl'],authorization)
  for name in ['Page.enable','Runtime.enable','Log.enable']:cdp.command(name)
  cdp.command('Fetch.enable',{'patterns':[{'urlPattern':'*'}],'handleAuthRequests':True});report=[]
  for width in [1920,1440,768,320]:
   cdp.console_errors=0;cdp.runtime_errors=0;cdp.command('Emulation.setDeviceMetricsOverride',{'width':width,'height':1000 if width>=1440 else 900,'deviceScaleFactor':1,'mobile':width==320})
   cdp.command('Page.navigate',{'url':HOST+'/'});deadline=time.monotonic()+45;ready=False
   while time.monotonic()<deadline:
    ready=cdp.evaluate("document.readyState==='complete' && !!document.querySelector('[data-threat-pulse=\"2.0\"] .tp-periods:not([hidden])')")
    if ready:break
    time.sleep(.2)
   need(ready,'New homepage Pulse did not load with JS enhancement')
   info=cdp.evaluate("""(()=>{const p=document.querySelector('[data-threat-pulse]'),m=document.querySelector('main');return {width:innerWidth,documentWidth:document.documentElement.scrollWidth,mainWidth:m.getBoundingClientRect().width,pulseHeight:p.getBoundingClientRect().height,cards:p.querySelectorAll('[data-pulse-kpi]').length,columns:getComputedStyle(p.querySelector('.tp-grid')).gridTemplateColumns.split(' ').length,hasOverflow:document.documentElement.scrollWidth>innerWidth+1,fullDashboardAbsent:!document.querySelector('[data-threat-dashboard]'),signalLink:!!p.querySelector('.tp-signal a[href^="https://"]'),exploreLink:p.querySelector('.tp-explore').href.endsWith('/threat-intelligence/')}})()""")
   info['periodInteraction']=cdp.evaluate("""(()=>{const root=document.querySelector('[data-threat-pulse]');let ok=true;for(const days of [7,30,90]){root.querySelector('[data-pulse-period="'+days+'"]').click();ok=ok&&root.querySelector('[data-pulse-period="'+days+'"]').getAttribute('aria-pressed')==='true';for(const chart of root.querySelectorAll('[data-pulse-series]')){const raw=JSON.parse(chart.dataset.pulseSeries),rows=Object.entries(raw).slice(-days),valid=rows.length===days&&rows.filter(r=>r[1]>0).length>=2;ok=ok&&chart.querySelectorAll('tbody tr').length===days&&chart.querySelector('svg').hasAttribute('hidden')===!valid;if(valid){const sum=rows.reduce((a,r)=>a+r[1],0);ok=ok&&chart.querySelector('[data-spark-summary]').textContent.includes(sum+' records');const svg=chart.querySelector('svg');svg.focus();svg.dispatchEvent(new KeyboardEvent('keydown',{key:'Home',bubbles:true}));ok=ok&&root.querySelector('[data-pulse-tooltip]').textContent.includes(rows[0][0]);}}}root.querySelector('[data-pulse-period="7"]').click();return ok})()""")
   info['severityInteraction']=cdp.evaluate("""(()=>{const r=document.querySelector('[data-threat-pulse]');let ok=r.querySelectorAll('.tp-legend button').length===6;for(const b of r.querySelectorAll('[data-pulse-tip]')){b.focus();ok=ok&&r.querySelector('[data-pulse-tooltip]').textContent===b.dataset.pulseTip;b.click();ok=ok&&r.querySelector('[data-pulse-tooltip]').textContent===b.dataset.pulseTip;}return ok})()""")
   if width<1024:
    info['mobileMenu']=cdp.evaluate("(()=>{const b=document.querySelector('[data-menu-toggle]'),n=document.querySelector('#site-navigation');if(!b||!n||b.hidden)return false;b.click();const ok=b.getAttribute('aria-expanded')==='true'&&!n.hidden;b.click();return ok&&n.hidden})()")
   else:info['mobileMenu']=None
   cdp.evaluate("document.querySelector('[data-threat-pulse]').scrollIntoView();true")
   for selector,prefix in [('main','homepage'),('[data-threat-pulse]','pulse')]:
    rectangle=cdp.evaluate("(()=>{const r=document.querySelector("+json.dumps(selector)+").getBoundingClientRect();return {x:r.x+scrollX,y:r.y+scrollY,width:r.width,height:r.height,scale:1}})()")
    image=cdp.command('Page.captureScreenshot',{'format':'png','captureBeyondViewport':True,'clip':rectangle});name=prefix+'-'+str(width)+'.png';(output/name).write_bytes(base64.b64decode(image['data']))
   info.update({'console_error_count':cdp.console_errors,'runtime_exception_count':cdp.runtime_errors});report.append(info);print('BROWSER: '+json.dumps(info))
  (output/'report.json').write_text(json.dumps({'url':HOST+'/','screens':report,'password_saved':False,'source':'real staging in existing Edge; no fixtures'},indent=2))
  need(all(r['periodInteraction'] and r['severityInteraction'] and (r['mobileMenu'] is not False) and not r['hasOverflow'] and r['cards']==4 and r['fullDashboardAbsent'] and r['exploreLink'] and r['columns']==(4 if r['width']>=1100 else 2 if r['width']>=600 else 1) and r['mainWidth']<=1281 and r['runtime_exception_count']==0 and r['console_error_count']==0 for r in report),'Browser acceptance failed; screenshots and sanitized report retained')
  print('PASS: real 320/768/1440/1920 browser screenshots, period/keyboard/severity/menu checks');print('DIRECTORY: '+str(output))
 finally:
  if cdp:
   try:cdp.command('Browser.close')
   except (OSError,RuntimeError):pass
   cdp.close()
  if process:
   try:process.wait(timeout=10)
   except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=10)
  # Only this newly created disposable browser profile, never the normal Edge profile.
  try:shutil.rmtree(profile)
  except OSError:print('WARNING: temporary isolated browser profile retained; path not printed')
if __name__=='__main__':
 try:main()
 except Exception as error:
  print('BLOCKED: browser screenshot check');print('Error type: '+type(error).__name__)
  if isinstance(error,RuntimeError):print('Reason: '+str(error))
  print('No credentials, cookies or raw page contents printed.');sys.exit(1)
