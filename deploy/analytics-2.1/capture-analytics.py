#!/usr/bin/env python3
"""Windows 11 / existing Edge only. Hidden staging Basic Auth, isolated temporary profile.
No packages installed. Saves screenshots and a sanitized layout/console report locally.
"""
import base64,getpass,hashlib,http.client,html.parser,json,os,pathlib,secrets,shutil,socket,struct,subprocess,sys,tempfile,time,urllib.error,urllib.parse,urllib.request
P=pathlib.Path;HOST='https://staging.cyberdat.eu'
def need(ok,message):
 if not ok:raise RuntimeError(message)
def basic_password_valid(value):
 return isinstance(value,str) and bool(value) and len(value.encode('utf-8'))<=4096 and not any(ord(c)<32 or ord(c)==127 for c in value)
def read_basic_password(window=False):
 if not window:
  value=getpass.getpass('EXISTING staging HTTP Basic Auth password (hidden): ')
  need(basic_password_valid(value),'Empty password or control character from console paste; use --password-window for local input')
  return value
 try:
  import tkinter as tk
  from tkinter import ttk,messagebox
 except ImportError:raise RuntimeError('Python Tkinter is unavailable; no package installed. Verify Basic Auth in a private browser window.') from None
 app=tk.Tk();app.title('CyberDat — local Basic Auth input');app.resizable(False,False);result=[]
 frame=ttk.Frame(app,padding=18);frame.grid(sticky='nsew')
 ttk.Label(frame,text='https://staging.cyberdat.eu',font=('Segoe UI',11,'bold')).grid(row=0,column=0,columnspan=2,sticky='w',pady=(0,8))
 ttk.Label(frame,text='Username: cyberdat_staging_admin').grid(row=1,column=0,columnspan=2,sticky='w')
 ttk.Label(frame,text='Enter the FIRST site-access password, not WordPress or SSH.').grid(row=2,column=0,columnspan=2,sticky='w',pady=(6,12))
 ttk.Label(frame,text='Basic Auth password:').grid(row=3,column=0,sticky='w')
 entry=ttk.Entry(frame,show='*',width=48);entry.grid(row=4,column=0,columnspan=2,sticky='ew',pady=6)
 reveal=tk.BooleanVar(value=False);ttk.Checkbutton(frame,text='Show password locally',variable=reveal,command=lambda:entry.configure(show='' if reveal.get() else '*')).grid(row=5,column=0,columnspan=2,sticky='w')
 ttk.Label(frame,text='Password stays in memory; it is not printed or saved.').grid(row=6,column=0,columnspan=2,sticky='w',pady=(8,12))
 def submit(event=None):
  value=entry.get()
  if not basic_password_valid(value):messagebox.showwarning('Input required','Enter the existing Basic Auth password without newline/control characters.',parent=app);return
  result.append(value);entry.delete(0,'end');app.destroy()
 ttk.Button(frame,text='Continue',command=submit).grid(row=7,column=0,sticky='e',padx=(0,8));ttk.Button(frame,text='Cancel',command=app.destroy).grid(row=7,column=1,sticky='w')
 app.bind('<Return>',submit);app.protocol('WM_DELETE_WINDOW',app.destroy);app.after(100,lambda:entry.focus_force());app.mainloop()
 need(bool(result),'Local password input cancelled');return result[0]
class HomeState(html.parser.HTMLParser):
 def __init__(self):super().__init__(convert_charrefs=True);self.version=None;self.model=False;self.series=0;self.asset=False
 def handle_starttag(self,tag,attrs):
  a=dict(attrs)
  if 'data-threat-pulse' in a:self.version=a['data-threat-pulse']
  if 'data-pulse-periods' in a:
   try:value=json.loads(a['data-pulse-periods']);self.model=isinstance(value,dict) and all(str(n) in value.get('periods',{}) for n in [7,30,90])
   except (ValueError,TypeError):self.model=False
  if 'data-pulse-series' in a:self.series+=1
  if tag=='script' and urllib.parse.urlsplit(a.get('src','')).path.endswith('/assets/js/threat-pulse.js'):self.asset=True
class StagingRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):
  u=urllib.parse.urlsplit(newurl);need(u.scheme=='https' and u.netloc=='staging.cyberdat.eu','External staging redirect refused')
  return super().redirect_request(req,fp,code,msg,headers,newurl)
def home_preflight(authorization):
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),StagingRedirect())
 request=urllib.request.Request(HOST+'/',headers={'Authorization':authorization,'User-Agent':'CyberDat-Browser-Verification/2.1'})
 try:
  with opener.open(request,timeout=30) as response:status=response.status;body=response.read(4000000)
 except urllib.error.HTTPError as error:status=error.code;body=error.read(4000000)
 parser=HomeState();parser.feed(body.decode('utf-8','replace'))
 return {'http_status':status,'pulse_version':parser.version,'period_model_present':parser.model,'daily_series':parser.series,'pulse_script_enqueued':parser.asset}
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
   if allowed and u.path.endswith('/cyberdat-analytics/v1/records'):
    query=urllib.parse.parse_qs(u.query);self.analytics_filter={k:query.get(k,[''])[0] for k in ['group','value','date','days']}
   self.id+=1
   if allowed:
    headers=[{'name':k,'value':v} for k,v in request.get('headers',{}).items() if k.lower()!='authorization'];headers.append({'name':'Authorization','value':self.authorization});self.send({'id':self.id,'method':'Fetch.continueRequest','params':{'requestId':p['requestId'],'headers':headers}})
   else:self.send({'id':self.id,'method':'Fetch.failRequest','params':{'requestId':p['requestId'],'errorReason':'BlockedByClient'}})
  elif name=='Fetch.authRequired':
   self.id+=1;self.send({'id':self.id,'method':'Fetch.continueWithAuth','params':{'requestId':p['requestId'],'authChallengeResponse':{'response':'CancelAuth'}}})
  elif name=='Network.responseReceived':
   response=p.get('response',{});u=urllib.parse.urlsplit(response.get('url',''))
   if u.netloc=='staging.cyberdat.eu' and (p.get('type')=='Document' or u.path.endswith('/assets/js/threat-pulse.js')):
    if not hasattr(self,'network_status'):self.network_status={}
    self.network_status['document' if p.get('type')=='Document' else 'pulse_script']=int(response.get('status',0))
  elif name=='Runtime.exceptionThrown':
   self.runtime_errors+=1;detail=p.get('exceptionDetails',{});u=urllib.parse.urlsplit(detail.get('url',''))
   if not hasattr(self,'runtime_locations'):self.runtime_locations=[]
   if len(self.runtime_locations)<8:self.runtime_locations.append({'same_origin':u.netloc=='staging.cyberdat.eu','script':u.path if u.netloc=='staging.cyberdat.eu' and '/assets/js/' in u.path else None,'line':detail.get('lineNumber'),'column':detail.get('columnNumber')})
  elif name=='Log.entryAdded' and p.get('entry',{}).get('level')=='error':self.console_errors+=1
 def evaluate(self,code):return self.command('Runtime.evaluate',{'expression':code,'returnByValue':True})['result'].get('value')
 def close(self):self.s.close()
def debugging_port(text):
 lines=text.splitlines();need(len(lines)>=2 and lines[0].isdigit() and 1<=int(lines[0])<=65535,'Invalid isolated DevTools port file')
 need(lines[1].startswith('/devtools/browser/') and all(c.isalnum() or c in '/-' for c in lines[1]),'Invalid isolated DevTools browser path');return int(lines[0])
def edge_policies():
 if os.name!='nt':return {}
 import winreg
 result={}
 for label,hive in [('machine',winreg.HKEY_LOCAL_MACHINE),('user',winreg.HKEY_CURRENT_USER)]:
  for name in ['RemoteDebuggingAllowed','DeveloperToolsAvailability']:
   try:
    with winreg.OpenKey(hive,r'SOFTWARE\Policies\Microsoft\Edge',0,winreg.KEY_READ) as key:value,kind=winreg.QueryValueEx(key,name)
    result[label+'.'+name]=value if isinstance(value,int) else 'non-integer policy value'
   except FileNotFoundError:pass
   except OSError:result[label+'.'+name]='unreadable'
 return result
def main():
 need(os.name=='nt','Run on Windows 11; this script does not install a browser on the VPS')
 need(set(sys.argv[1:])<=set(['--visible','--password-window']) and len(set(sys.argv[1:]))==len(sys.argv[1:]),'Only --visible and --password-window are supported');visible='--visible' in sys.argv
 policies=edge_policies();print('EDGE POLICIES: '+json.dumps(policies),flush=True)
 need(not any(k.endswith('.RemoteDebuggingAllowed') and v==0 for k,v in policies.items()),'Edge remote debugging is disabled by policy; no policy was changed')
 candidates=[P(os.environ.get('PROGRAMFILES(X86)','C:/Program Files (x86)'))/'Microsoft/Edge/Application/msedge.exe',P(os.environ.get('PROGRAMFILES','C:/Program Files'))/'Microsoft/Edge/Application/msedge.exe'];browser=next((p for p in candidates if p.is_file()),None);need(browser is not None,'Existing Microsoft Edge not found')
 stamp=time.strftime('%Y%m%dT%H%M%SZ',time.gmtime());output=P.home()/('CyberDat-analytics-2.1-screenshots-'+stamp);output.mkdir(exist_ok=False);print('DIRECTORY: '+str(output),flush=True)
 profile=tempfile.mkdtemp(prefix='cyberdat-dashboard-edge-');port=None;process=None;cdp=None
 try:
  flags=['--disable-gpu','--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-component-update','--disable-sync','--disable-extensions','--remote-debugging-address=127.0.0.1','--remote-debugging-port=0','--user-data-dir='+profile,'about:blank']
  if not visible:flags.insert(0,'--headless=new')
  process=subprocess.Popen([str(browser),*flags],cwd=profile,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  opener=urllib.request.build_opener(urllib.request.ProxyHandler({}));deadline=time.monotonic()+60;target=None;last_error=None;active=P(profile)/'DevToolsActivePort'
  while time.monotonic()<deadline:
   try:
    if active.is_file():port=debugging_port(active.read_text(encoding='utf-8'))
    if port is not None:
     with opener.open('http://127.0.0.1:'+str(port)+'/json/list',timeout=2) as response:tabs=json.load(response)
     if isinstance(tabs,list):target=next((t for t in tabs if isinstance(t,dict) and t.get('type')=='page'),None)
     else:last_error='invalid_json_list'
     if target:break
   except (OSError,ValueError,RuntimeError) as error:last_error=type(error).__name__
   time.sleep(.25)
  startup={'mode':'visible' if visible else 'headless','launcher_exit_code':process.poll(),'active_port_file':active.is_file(),'port_discovered':port is not None,'last_http_error_type':last_error,'policies':policies}
  (output/'edge-startup.json').write_text(json.dumps(startup,indent=2));print('EDGE STARTUP: '+json.dumps(startup),flush=True)
  need(target is not None,'Isolated Edge DevTools not ready; see EDGE STARTUP diagnostics; no staging password requested')
  cdp=DevTools(target['webSocketDebuggerUrl'],'')
  print('PASS: isolated Edge DevTools connected; no staging request yet',flush=True)
  password=read_basic_password('--password-window' in sys.argv);authorization='Basic '+base64.b64encode(('cyberdat_staging_admin:'+password).encode()).decode();cdp.authorization=authorization
  preflight=home_preflight(authorization);print('HOME HTTP DIAGNOSTIC: '+json.dumps(preflight),flush=True)
  (output/'home-http.json').write_text(json.dumps(preflight,indent=2))
  need(preflight['http_status']!=401,'Staging rejected Basic Auth credentials; enter the existing Basic Auth password, not the WordPress or SSH password')
  need(preflight['http_status']==200,'Staging homepage HTTP status is not 200; see HOME HTTP DIAGNOSTIC')
  if not preflight['period_model_present']:
   time.sleep(5);preflight=home_preflight(authorization);print('HOME HTTP RECHECK: '+json.dumps(preflight),flush=True)
  need(preflight['pulse_version']=='2.1' and preflight['period_model_present'],'Server HTML has no valid 2.1 period model; browser/JS cannot fix this; see HOME HTTP DIAGNOSTIC')
  for name in ['Page.enable','Runtime.enable','Log.enable','Network.enable']:cdp.command(name)
  cdp.command('Fetch.enable',{'patterns':[{'urlPattern':'*'}],'handleAuthRequests':True});report=[]
  def wait(expression,seconds=45):
   end=time.monotonic()+seconds
   while time.monotonic()<end:
    if cdp.evaluate(expression):return True
    time.sleep(.15)
   return False
  def tap(selector):
   # getScreenCTM already includes each circle's rotate(-90); do not apply that rotation twice.
   code="""(()=>{const n=document.querySelector(SELECTOR);if(!n)return null;const details=n.closest('details');if(details)details.open=true;n.scrollIntoView({block:'center',inline:'nearest'});if(n.classList.contains('td-ring-segment')){const span=parseFloat(n.getAttribute('stroke-dasharray')),offset=Math.abs(parseFloat(n.getAttribute('stroke-dashoffset'))),angle=(3.6*(offset+span/2))*Math.PI/180,p=new DOMPoint(110+80*Math.cos(angle),110+80*Math.sin(angle)).matrixTransform(n.getScreenCTM());return {x:p.x,y:p.y};}const r=n.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2};})()""".replace('SELECTOR',json.dumps(selector))
   point=cdp.evaluate(code);need(point is not None,'Interactive element missing: '+selector)
   if width==320:
    cdp.command('Input.dispatchTouchEvent',{'type':'touchStart','touchPoints':[point]});cdp.command('Input.dispatchTouchEvent',{'type':'touchEnd','touchPoints':[]})
   else:
    cdp.command('Input.dispatchMouseEvent',{'type':'mousePressed','button':'left','clickCount':1,**point});cdp.command('Input.dispatchMouseEvent',{'type':'mouseReleased','button':'left','clickCount':1,**point})
  for width in [1920,1440,768,320]:
   cdp.console_errors=0;cdp.runtime_errors=0;cdp.command('Emulation.setDeviceMetricsOverride',{'width':width,'height':1000,'deviceScaleFactor':1,'mobile':width==320})
   cdp.command('Page.navigate',{'url':HOST+'/'})
   ready=wait("document.readyState==='complete'&&!!document.querySelector('[data-threat-pulse=\"2.1\"] .tp-periods:not([hidden])')")
   if not ready:
    dom=cdp.evaluate("""(()=>{const r=document.querySelector('[data-threat-pulse]'),b=r?.querySelector('.tp-periods');return {readyState:document.readyState,path:location.pathname,pulseVersion:r?.dataset.threatPulse||null,periodModelPresent:!!r?.dataset.pulsePeriods&&r.dataset.pulsePeriods!=='null',controlsPresent:!!b,controlsHidden:b?.hidden??null,series:r?.querySelectorAll('[data-pulse-series]').length||0,pulseScriptPresent:[...document.scripts].some(s=>s.src.includes('/assets/js/threat-pulse.js'))}})()""")
    diagnostic={'width':width,'dom':dom,'http':getattr(cdp,'network_status',{}),'runtime_errors':cdp.runtime_errors,'error_locations':getattr(cdp,'runtime_locations',[])}
    print('HOME BROWSER DIAGNOSTIC: '+json.dumps(diagnostic),flush=True);(output/'home-browser-failure.json').write_text(json.dumps(diagnostic,indent=2))
    shot=cdp.command('Page.captureScreenshot',{'format':'png'});(output/('home-failure-'+str(width)+'.png')).write_bytes(base64.b64decode(shot['data']))
   need(ready,'Period-aware homepage unavailable; see HOME HTTP/BROWSER diagnostics')
   info={'width':width,'periods':[]}
   for days in [7,30,90]:
    tap('[data-pulse-period="'+str(days)+'"]')
    good=cdp.evaluate("""(()=>{const r=document.querySelector('[data-threat-pulse]'),p=JSON.parse(r.dataset.pulsePeriods).periods[DAYS];return [...r.querySelectorAll('[data-pulse-kpi]')].every(n=>Number(n.dataset.value)===p.counts[n.dataset.pulseKpi])&&r.querySelector('[data-pulse-window]').textContent.includes(p.start)&&r.querySelector('[data-pulse-window]').textContent.includes(p.end)&&r.querySelectorAll('tbody tr').length===2*DAYS})()""".replace('DAYS',str(days)))
    need(good,'KPI/period/series browser mismatch');info['periods'].append(days)
   tap('[data-pulse-period="7"]');rectangle=cdp.evaluate("(()=>{const r=document.querySelector('[data-threat-pulse]').getBoundingClientRect();return {x:r.x+scrollX,y:r.y+scrollY,width:r.width,height:r.height,scale:1}})()")
   image=cdp.command('Page.captureScreenshot',{'format':'png','captureBeyondViewport':True,'clip':rectangle});(output/('pulse-'+str(width)+'.png')).write_bytes(base64.b64decode(image['data']))
   cdp.command('Page.navigate',{'url':HOST+'/threat-intelligence/'});need(wait("document.readyState==='complete'&&!!document.querySelector('.ta-browse')"),'Drill-down enhancement unavailable')
   cdp.evaluate("""(()=>{const root=document.querySelector('[data-analytics-endpoint]');window.__cdtaCaptureTrigger=null;const remember=event=>{if(event.type==='keydown'&&!['Enter',' '].includes(event.key))return;const node=event.target.closest('.td-chart-point,[data-drill-group]');if(node)window.__cdtaCaptureTrigger=node;};root.addEventListener('click',remember,true);root.addEventListener('keydown',remember,true);return true})()""")
   info['groups']=[]
   cases=[('[data-chart-id=cvss-severity] [data-drill-value="'+v+'"]','severity:'+v) for v in ['Critical','High','Medium','Low','None','Unrated']]+[('[data-drill-group=overlap][data-drill-value='+v+']','overlap:'+v) for v in ['shared','kev_only','nvd_only']]+[('[data-chart-id=ransomware] [data-drill-value='+v+']','ransomware:'+v) for v in ['known','not_known']]+[('[data-chart-id=advisory-sources] [data-drill-value='+v+']','advisory:'+v) for v in ['cisa-advisories','cert-eu','msrc']]+[('[data-chart-id='+v+'] .td-chart-point','day:'+v) for v in ['kev-additions','nvd-trends']]
   for selector,label in cases:
    if label=='severity:Unrated':
     cdp.evaluate("(()=>{const n=document.querySelector("+json.dumps(selector)+");const d=n.closest('details');if(d)d.open=true;n.scrollIntoView({block:'center'});n.focus();return true})()")
     cdp.command('Input.dispatchKeyEvent',{'type':'keyDown','key':'Enter','code':'Enter','windowsVirtualKeyCode':13});cdp.command('Input.dispatchKeyEvent',{'type':'keyUp','key':'Enter','code':'Enter','windowsVirtualKeyCode':13})
    else:tap(selector)
    need(wait("document.querySelector('[data-analytics-dialog]').open&&document.querySelector('[data-ta-status]').textContent.includes('matching records')"),'Record request did not succeed: '+label)
    expected_group,expected_value=label.split(':',1)
    if expected_group=='day':expected_value='kev' if expected_value=='kev-additions' else 'nvd'
    observed=getattr(cdp,'analytics_filter',{})
    need(observed.get('group')==expected_group and observed.get('value')==expected_value,'Clicked chart sent a different filter: '+label+' observed='+json.dumps(observed))
    result=cdp.evaluate("(()=>{const d=document.querySelector('[data-analytics-dialog]');return {rows:d.querySelectorAll('.ta-record').length,links:[...d.querySelectorAll('.ta-record a')].every(a=>a.href.startsWith('https://')),overflow:d.scrollWidth>d.clientWidth+1,focusInside:d.contains(document.activeElement)}})()")
    need(result['rows']<=20 and result['links'] and not result['overflow'] and result['focusInside'],'Panel bounds/links/focus failure');info['groups'].append(label)
    if label=='severity:High':
     cdp.evaluate("document.querySelector('[data-ta-form] select').value='cvss_desc';true");tap('[data-ta-form] button');need(wait("document.querySelector('[data-ta-status]').textContent.includes('matching records')"),'Sort request failed')
     if cdp.evaluate("!document.querySelector('[data-ta-page=next]').disabled"):
      tap('[data-ta-page=next]');need(wait("document.querySelector('[data-ta-page-label]').textContent.startsWith('Page 2')"),'Pagination failed')
     cve=cdp.evaluate("document.querySelector('.ta-cve')?.textContent||''")
     if cve:
      cdp.evaluate("document.querySelector('[data-ta-form] input').value="+json.dumps(cve)+";true");tap('[data-ta-form] button');need(wait("document.querySelector('[data-ta-status]').textContent.startsWith('1 matching records')"),'CVE search failed')
     image=cdp.command('Page.captureScreenshot',{'format':'png'});(output/('records-'+str(width)+'.png')).write_bytes(base64.b64decode(image['data']))
    title=cdp.evaluate("document.querySelector('[data-ta-title]').textContent");need(title not in ['kev_only','nvd_only','shared','known','not_known'],'Technical filter title leaked into panel')
    if label=='severity:Critical':tap('[data-ta-close]')
    else:
     cdp.command('Input.dispatchKeyEvent',{'type':'keyDown','key':'Escape','code':'Escape','windowsVirtualKeyCode':27});cdp.command('Input.dispatchKeyEvent',{'type':'keyUp','key':'Escape','code':'Escape','windowsVirtualKeyCode':27})
    need(wait("!document.querySelector('[data-analytics-dialog]').open",5),'Panel did not close')
    # Native dialog close queues a close event; aria/focus restoration may follow open=false.
    focus_ok=wait("!!window.__cdtaCaptureTrigger&&document.activeElement===window.__cdtaCaptureTrigger",5)
    if not focus_ok:
     detail=cdp.evaluate("""(()=>{const meta=n=>n?{tag:n.tagName,role:n.getAttribute('role'),group:n.dataset?.drillGroup||null,value:n.dataset?.drillValue||null,connected:n.isConnected}:null;return {active:meta(document.activeElement),trigger:meta(window.__cdtaCaptureTrigger),dialogOpen:document.querySelector('[data-analytics-dialog]').open}})()""")
     diagnostic={'width':width,'case':label,'filter':observed,'focus':detail};print('FOCUS DIAGNOSTIC: '+json.dumps(diagnostic),flush=True);(output/'focus-failure.json').write_text(json.dumps(diagnostic,indent=2))
     shot=cdp.command('Page.captureScreenshot',{'format':'png'});(output/('focus-failure-'+str(width)+'.png')).write_bytes(base64.b64decode(shot['data']))
    need(focus_ok,'Focus did not return to the actual chart trigger after close: '+label)
   info['dayPeriods']=[]
   for chart in ['kev-additions','nvd-trends']:
    for days in [7,30,90]:
     base='[data-chart-id='+chart+']';tap(base+' [data-period="'+str(days)+'"]');tap(base+' .td-chart-point')
     need(wait("document.querySelector('[data-ta-status]').textContent.includes('matching records')"),'Day/period drill request failed')
     need(str(days)+'D' in cdp.evaluate("document.querySelector('[data-ta-title]').textContent"),'Drill lost the selected day period')
     tap('[data-ta-close]');need(cdp.evaluate("document.querySelector("+json.dumps(base+' [data-chart-line]')+").dataset.activePeriod")==str(days),'Chart period reset after closing records');info['dayPeriods'].append(chart+':'+str(days))
   info['overflow']=cdp.evaluate('document.documentElement.scrollWidth>innerWidth+1')
   if width<1024:
    tap('[data-menu-toggle]');need(cdp.evaluate("document.querySelector('[data-menu-toggle]').getAttribute('aria-expanded')==='true'"),'Mobile menu failed');tap('[data-menu-toggle]')
   rectangle=cdp.evaluate("(()=>{const r=document.querySelector('main').getBoundingClientRect();return {x:r.x+scrollX,y:r.y+scrollY,width:r.width,height:r.height,scale:1}})()")
   image=cdp.command('Page.captureScreenshot',{'format':'png','captureBeyondViewport':True,'clip':rectangle});(output/('dashboard-'+str(width)+'.png')).write_bytes(base64.b64decode(image['data']))
   info.update({'console_errors':cdp.console_errors,'runtime_errors':cdp.runtime_errors});report.append(info);print('BROWSER: '+json.dumps(info))
  (output/'report.json').write_text(json.dumps({'url':HOST,'screens':report,'source':'real staging in existing Edge; no fixtures','password_saved':False},indent=2))
  need(all(not r['overflow'] and not r['console_errors'] and not r['runtime_errors'] for r in report),'Browser/overflow/console acceptance failed; report retained')
  print('PASS: period KPIs, all chart groups, records/search/pagination/sort/Escape, four widths, touch at 320 and screenshots');print('DIRECTORY: '+str(output))
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
