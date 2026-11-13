import sys,os,pathlib,importlib.util,json,getpass,http.cookiejar,urllib.request,urllib.parse,re,html,datetime
sys.dont_write_bytecode=True
P=pathlib.Path;D=P(__file__).parent;spec=importlib.util.spec_from_file_location('manager',D/'manage.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);os.chdir(m.m.RUNTIME)
basic=getpass.getpass('EXISTING staging HTTP Basic Auth password (hidden): ');wp_password=getpass.getpass('EXISTING staging WORDPRESS password (hidden; login check only): ')
code="$p=json_decode(stream_get_contents(STDIN),true);$u=get_user_by('login','cyberdat_staging_admin');echo wp_json_encode(['ok'=>$u&&user_can($u,'manage_options')&&wp_check_password($p['password'],$u->user_pass,$u->ID),'cookie'=>LOGGED_IN_COOKIE]);"
auth=json.loads(m.m.wp('eval',code,data=json.dumps({'password':wp_password}).encode()).stdout);m.m.need(auth['ok'],'Existing WordPress password mismatch; no reset performed')
jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),m.m.Redirect());m.m.fetch('/wp-login.php',basic,opener);form=urllib.parse.urlencode({'log':'cyberdat_staging_admin','pwd':wp_password,'redirect_to':m.m.HOST+'/wp-admin/','testcookie':'1'}).encode();status,_,login=m.m.fetch('/wp-login.php',basic,opener,form)
report={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'password_valid':True,'credentials_changed':False,'mfa_actual_otp':'UNVERIFIED'}
if not any(c.name==auth['cookie'] for c in jar):
 report['authentication']='challenge_or_incomplete';report['admin_pages']='UNVERIFIED';report['second_factor_challenge_detected']=bool(re.search(rb'two.factor|one.time|verification.code|authcode|totp',login,re.I))
else:
 report['authentication']='existing_password_login_succeeded';report['second_factor_challenge_observed']=False;report['admin_pages']={};last=''
 for path,marker in [('/wp-admin/admin.php?page=cyberdat-research',b'Research Queue'),('/wp-admin/admin.php?page=cyberdat-content',b'Content Queue')]:
  status,_,body=m.m.fetch(path,basic,opener);m.m.need(status==200 and marker in body,'Authenticated queue route failed');report['admin_pages'][path]={'http':status,'marker':True};last=body.decode(errors='replace')
 logout=re.search(r'href=[\"\x27]([^\"\x27]*wp-login\.php\?action=logout[^\"\x27]*)',last)
 if logout:
  url=html.unescape(logout[1]);parts=urllib.parse.urlsplit(url);m.m.need(not parts.netloc or parts.netloc=='staging.cyberdat.eu','External logout rejected');m.m.fetch(parts.path+'?'+parts.query,basic,opener);report['test_session_logged_out']=True
 else:report['test_session_logged_out']=False
(m.B/'admin-verification.json').write_text(json.dumps(report,indent=2));print(json.dumps(report));print('No capability/MFA reset, queue action, job processing or publication performed; actual OTP/browser flow not claimed')
