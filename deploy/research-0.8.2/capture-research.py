#!/usr/bin/env python3
"""Windows 11 / existing Edge only. Hidden staging Basic Auth, isolated temporary profile.
No packages installed. Saves screenshots and a sanitized layout/console report locally.
"""
import base64,getpass,hashlib,http.client,html.parser,json,os,pathlib,re,secrets,shutil,socket,struct,subprocess,sys,tempfile,time,urllib.error,urllib.parse,urllib.request
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
def safe_resource(value):
 try:
  u=urllib.parse.urlsplit(value);host=u.hostname
  path=u.path if host=='staging.cyberdat.eu' and (u.path.startswith(('/wp-content/','/wp-includes/','/wp-json/')) or u.path in ['/','/favicon.ico']) and len(u.path)<=256 else None
  return {'host':host,'path':path}
 except ValueError:return {'host':None,'path':None}
def console_metadata(entry):
 text=entry.get('text','');status=re.search(r'status(?: of)? ([1-5][0-9]{2})\b',text,re.I);resource=safe_resource(entry.get('url',''))
 category='content_security_policy' if 'content security policy' in text.lower() else 'permissions_policy' if 'permissions-policy' in text.lower() else 'resource_error' if entry.get('source')=='network' else 'other'
 links=[safe_resource(url) for url in re.findall(r'https?://[^\s\x22\x27<>]+',text)[:3]]
 return {'source':entry.get('source'),'category':category,'resource':resource,'referenced_resources':links,'http_status':int(status.group(1)) if status else None,'net_errors':re.findall(r'net::[A-Z0-9_]+',text)[:3],'directives':sorted(set(re.findall(r'\b(?:default|script|style|img|font|connect|frame|worker)-src\b',text)))}
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
   else:
    if not hasattr(self,'blocked_external_hosts'):self.blocked_external_hosts=set()
    self.blocked_external_hosts.add(u.hostname)
    self.send({'id':self.id,'method':'Fetch.failRequest','params':{'requestId':p['requestId'],'errorReason':'BlockedByClient'}})
  elif name=='Fetch.authRequired':
   self.id+=1;self.send({'id':self.id,'method':'Fetch.continueWithAuth','params':{'requestId':p['requestId'],'authChallengeResponse':{'response':'CancelAuth'}}})
  elif name=='Network.responseReceived':
   response=p.get('response',{});u=urllib.parse.urlsplit(response.get('url',''))
   if int(response.get('status',0))>=400:
    if not hasattr(self,'failed_resources'):self.failed_resources=[]
    if len(self.failed_resources)<12:self.failed_resources.append({**safe_resource(response.get('url','')),'status':int(response.get('status',0)),'type':p.get('type')})
   if u.netloc=='staging.cyberdat.eu' and u.path.endswith('/cyberdat-analytics/v1/records'):
    q=urllib.parse.parse_qs(u.query);self.record_response={'status':int(response.get('status',0)),**{k:q.get(k,[''])[0] for k in ['group','value','date','days']}}
   if u.netloc=='staging.cyberdat.eu' and (p.get('type')=='Document' or u.path.endswith('/assets/js/threat-pulse.js')):
    if not hasattr(self,'network_status'):self.network_status={}
    self.network_status['document' if p.get('type')=='Document' else 'pulse_script']=int(response.get('status',0))
  elif name=='Runtime.exceptionThrown':
   self.runtime_errors+=1;detail=p.get('exceptionDetails',{});u=urllib.parse.urlsplit(detail.get('url',''))
   if not hasattr(self,'runtime_locations'):self.runtime_locations=[]
   if len(self.runtime_locations)<8:self.runtime_locations.append({'same_origin':u.netloc=='staging.cyberdat.eu','script':u.path if u.netloc=='staging.cyberdat.eu' and '/assets/js/' in u.path else None,'line':detail.get('lineNumber'),'column':detail.get('columnNumber')})
  elif name=='Log.entryAdded' and p.get('entry',{}).get('level')=='error':
   if not hasattr(self,'console_entries'):self.console_entries=[]
   if len(self.console_entries)<12:self.console_entries.append(console_metadata(p['entry']))
   entry=p['entry'];u=urllib.parse.urlsplit(entry.get('url',''));status=re.search(r'status(?: of)? (409|503)\b',entry.get('text',''),re.I)
   if entry.get('source')=='network' and u.netloc=='staging.cyberdat.eu' and u.path.endswith('/cyberdat-analytics/v1/records') and status:
    # Report expected HTTP revalidation separately; never suppress JS exceptions or other errors.
    key='projection_conflict_http' if status.group(1)=='409' else 'source_busy_http';setattr(self,key,getattr(self,key,0)+1)
   elif entry.get('source')=='network' and u.hostname=='secure.gravatar.com' and u.scheme=='https' and 'secure.gravatar.com' in getattr(self,'blocked_external_hosts',set()) and re.findall(r'net::[A-Z0-9_]+',entry.get('text',''))==['net::ERR_BLOCKED_BY_CLIENT']:
    # This harness blocked the external avatar itself; retain it separately as evidence.
    self.expected_external_avatar_blocks=getattr(self,'expected_external_avatar_blocks',0)+1
   else:self.console_errors+=1
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
 import ctypes;need(not ctypes.windll.shell32.IsUserAnAdmin(),'Use ordinary CMD, not an elevated Administrator terminal');visible=True
 policies=edge_policies();print('EDGE POLICIES: '+json.dumps(policies),flush=True)
 need(not any(k.endswith('.RemoteDebuggingAllowed') and v==0 for k,v in policies.items()),'Edge remote debugging is disabled by policy; no policy was changed')
 candidates=[P(os.environ.get('PROGRAMFILES(X86)','C:/Program Files (x86)'))/'Microsoft/Edge/Application/msedge.exe',P(os.environ.get('PROGRAMFILES','C:/Program Files'))/'Microsoft/Edge/Application/msedge.exe'];browser=next((p for p in candidates if p.is_file()),None);need(browser is not None,'Existing Microsoft Edge not found')
 stamp=time.strftime('%Y%m%dT%H%M%SZ',time.gmtime());output=P.home()/('CyberDat-research-0.8.2-browser-'+stamp);output.mkdir(exist_ok=False);print('DIRECTORY: '+str(output),flush=True)
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
  password=read_basic_password(True);authorization='Basic '+base64.b64encode(('cyberdat_staging_admin:'+password).encode()).decode();cdp.authorization=authorization
  preflight=home_preflight(authorization);print('HOME HTTP DIAGNOSTIC: '+json.dumps(preflight),flush=True)
  (output/'home-http.json').write_text(json.dumps(preflight,indent=2))
  need(preflight['http_status']!=401,'Staging rejected Basic Auth credentials; enter the existing Basic Auth password, not the WordPress or SSH password')
  need(preflight['http_status']==200,'Staging homepage HTTP status is not 200; see HOME HTTP DIAGNOSTIC')
  for name in ['Page.enable','Runtime.enable','Log.enable','Network.enable']:cdp.command(name)
  cdp.command('Fetch.enable',{'patterns':[{'urlPattern':'*'}],'handleAuthRequests':True});report=[]
  def wait(expression,seconds=45):
   deadline=time.monotonic()+seconds
   while time.monotonic()<deadline:
    if cdp.evaluate(expression):return True
    time.sleep(.2)
   return False
  def ready():
   return wait("document.readyState==='complete'&&!!document.querySelector('body.wp-admin #wpcontent h1')")
  def screenshot(name):
   image=cdp.command('Page.captureScreenshot',{'format':'png','captureBeyondViewport':False});(output/name).write_bytes(base64.b64decode(image['data']))
  def submit(fields):
   cdp.command('Page.addScriptToEvaluateOnNewDocument',{'source':'window.__researchCheckLoaded=true;'})
   old=cdp.evaluate('location.href')
   code="""(()=>{const form=document.querySelector('#wpbody-content .wrap form[method=get]');if(!form)return false;for(const [key,value] of Object.entries(FIELDS)){const n=form.elements.namedItem(key);if(!n)return false;n.value=value;}form.requestSubmit();return true;})()""".replace('FIELDS',json.dumps(fields))
   need(cdp.evaluate(code),'Queue filter controls missing')
   need(wait('location.href!=='+json.dumps(old)), 'Filter did not navigate')
   need(ready(),'Filtered admin queue unavailable')
  cdp.command('Emulation.setDeviceMetricsOverride',{'width':1440,'height':1000,'deviceScaleFactor':1,'mobile':False})
  cdp.command('Page.navigate',{'url':HOST+'/wp-login.php?redirect_to='+urllib.parse.quote(HOST+'/wp-admin/admin.php?page=cyberdat-research',safe='')})
  print('ACTION: In the isolated Edge window, log in as cyberdat_staging_admin using the WORDPRESS password. Do not paste it into CMD. Waiting up to 3 minutes.',flush=True)
  need(wait("location.pathname.startsWith('/wp-admin/')&&!!document.querySelector('#wpadminbar')",180),'WordPress login not completed; no password reset attempted')
  cdp.command('Page.navigate',{'url':HOST+'/wp-admin/admin.php?page=cyberdat-research'});need(ready(),'Research Queue unavailable after login')
  report=[]
  for stream in ['news','research','papers']:
   submit({'stream':stream,'source':'','q':''})
   rows=cdp.evaluate("document.querySelectorAll('#wpbody-content .wrap table.widefat tbody tr').length")
   need(isinstance(rows,int) and 1<=rows<=25,'Unexpected or empty queue for '+stream)
   need(cdp.evaluate("[...document.querySelectorAll('#wpbody-content table.widefat tbody td:first-child a')].every(a=>a.protocol==='https:'&&!!a.hostname)"),'Invalid source links')
   if stream=='papers':
    need(cdp.evaluate("[...document.querySelectorAll('#wpbody-content details summary')].some(n=>n.textContent.includes('Scientific metadata'))"),'Scientific metadata missing')
    cdp.evaluate("const n=[...document.querySelectorAll('#wpbody-content details')].find(n=>n.querySelector('summary')?.textContent.includes('Scientific metadata'));if(n)n.open=true;")
   screenshot('queue-'+stream+'-1440.png');report.append({'check':'stream','stream':stream,'rows':rows,'status':'PASS'});print('PASS: '+stream+' filter, bounded rows and HTTPS source links',flush=True)
  submit({'stream':'papers','source':'crossref','q':''})
  doi=cdp.evaluate("(()=>{const a=[...document.querySelectorAll('#wpbody-content table.widefat tbody td:first-child a')].find(a=>a.hostname==='doi.org');return a?decodeURIComponent(a.pathname.slice(1)):null;})()")
  need(isinstance(doi,str) and re.fullmatch(r'10\.\d{4,9}/[^\s<>]+',doi),'No Crossref DOI available for search check')
  submit({'q':doi});need(cdp.evaluate("document.querySelectorAll('#wpbody-content table.widefat tbody tr').length>=1"),'DOI search returned no record');need(cdp.evaluate("document.querySelector('#wpbody-content table.widefat tbody').textContent.includes("+json.dumps(doi)+")"),'DOI search result does not match');screenshot('paper-doi-search-1440.png');print('PASS: Crossref filter and real DOI search',flush=True)
  submit({'q':''})
  pagination=cdp.evaluate("(()=>{const a=[...document.querySelectorAll('#wpbody-content a.button')].find(a=>a.textContent.trim()==='Next');return a?.href||null;})()")
  if pagination:
   u=urllib.parse.urlsplit(pagination);need(u.scheme=='https' and u.netloc=='staging.cyberdat.eu' and u.path=='/wp-admin/admin.php','Unexpected pagination destination')
   cdp.evaluate("[...document.querySelectorAll('#wpbody-content a.button')].find(a=>a.textContent.trim()==='Next').click()")
   need(wait("new URL(location.href).searchParams.get('paged')==='2'") and ready(),'Second queue page unavailable');print('PASS: server pagination',flush=True);report.append({'check':'pagination','status':'PASS'})
  else:report.append({'check':'pagination','status':'UNVERIFIED','reason':'Not enough current Crossref results for a second page'})
  cdp.command('Page.navigate',{'url':HOST+'/wp-admin/admin.php?page=cyberdat-sources'});need(ready(),'Source Registry unavailable');need(cdp.evaluate("document.querySelector('#wpbody-content h1').textContent.includes('Source Registry')"),'Wrong registry page')
  registry_rows=cdp.evaluate("document.querySelectorAll('#wpbody-content table.widefat tbody tr').length");need(registry_rows>=40,'Source catalog incomplete');screenshot('source-registry-1440.png');print('PASS: Source Registry available; rows='+str(registry_rows),flush=True)
  for width in [768,320]:
   cdp.command('Emulation.setDeviceMetricsOverride',{'width':width,'height':900,'deviceScaleFactor':1,'mobile':width==320});time.sleep(.4)
   screenshot('source-registry-'+str(width)+'.png');overflow=cdp.evaluate('document.documentElement.scrollWidth>innerWidth+1');report.append({'check':'admin_layout','width':width,'horizontal_overflow':overflow,'overflow_elements':cdp.evaluate("[...document.querySelectorAll('body *')].filter(n=>{const r=n.getBoundingClientRect();return r.width>0&&r.right>innerWidth+1&&getComputedStyle(n).visibility!=='hidden';}).slice(0,8).map(n=>({tag:n.tagName,classes:typeof n.className==='string'?n.className.slice(0,160):'',right:Math.round(n.getBoundingClientRect().right)}))") if overflow else [],'human_visual_review':'UNVERIFIED'})
  report.append({'check':'console','console_errors':cdp.console_errors,'runtime_errors':cdp.runtime_errors,'expected_external_avatar_blocks':getattr(cdp,'expected_external_avatar_blocks',0),'failed_resources':getattr(cdp,'failed_resources',[]),'console_diagnostics':getattr(cdp,'console_entries',[])})
  (output/'report.json').write_text(json.dumps({'url':HOST,'checks':report,'source_registry_rows':registry_rows,'editorial_changes':False,'source_toggles':False,'passwords_saved':False},indent=2))
  need(cdp.runtime_errors==0 and cdp.console_errors==0,'Unexpected browser console/runtime errors recorded; report retained')
  need(all(not row.get('horizontal_overflow',False) for row in report),'Admin layout overflow recorded; report retained')
  print('PASS: read-only Research Queue browser checks; screenshots and report saved. No review/status/classification/grouping/source settings changed.');print('DIRECTORY: '+str(output))
 finally:
  if cdp:
   try:cdp.command('Browser.close')
   except (OSError,RuntimeError):pass
   cdp.close()
  if process:
   try:process.wait(timeout=10)
   except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=10)
  try:shutil.rmtree(profile)
  except OSError:print('WARNING: this disposable browser profile could not be removed; no normal profile touched')
if __name__=='__main__':
 try:main()
 except Exception as error:
  print('BLOCKED: Research Queue browser check; type='+type(error).__name__)
  if isinstance(error,RuntimeError):print('Reason: '+str(error))
  print('No credentials, cookies or raw page contents printed.');sys.exit(1)
