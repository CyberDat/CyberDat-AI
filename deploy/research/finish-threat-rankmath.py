#!/usr/bin/env python3
"""Confirm and fix only Rank Math's supported free no-account wizard skip on staging.
No plugin code patches, accounts, APIs, manual SEO tags, timer or Research changes.
"""
import argparse,datetime,fcntl,getpass,hashlib,importlib.util,json,os,pathlib,sys
P=pathlib.Path;B=P(__file__).resolve().parent
phase='preflight';repair_backup=None

def need(ok,message):
 if not ok:raise RuntimeError(message)
def repair_needed(state):
 need(state.get('rank_math_active') is True and state.get('helper_available') is True,'Rank Math is not active/available; no repair applied')
 if not state['registration_invalid']:return False
 need(isinstance(state['skip_value'],(str,int,bool,type(None))),'Unexpected skip option type; no override applied')
 need(state['skip_value'] in (None,False,0,'','0') and state.get('constant_skip') is not True,'Inconsistent registration state; no override applied')
 return True

def main():
 global phase,repair_backup
 parser=argparse.ArgumentParser();parser.add_argument('--finish',action='store_true');args=parser.parse_args();need(args.finish and os.geteuid()==0,'Owner sudo and --finish required');os.umask(0o077)
 lock=P('/run/lock/cyberdat-staging-seo.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 for line in (B/'BUNDLE-SHA256SUMS').read_text().splitlines():
  expected,name=line.split(maxsplit=1);path=B/name;need(path.resolve().is_relative_to(B) and not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest()==expected,'Bundle integrity mismatch')
 spec=importlib.util.spec_from_file_location('threat_deployer',B/'deploy-threat-2.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 original_backup=P('/var/backups/cyberdat-staging/threat-2.0-20261108T194129Z')
 identity=module.state();need(identity[:4]==['staging','cyberdat_staging',module.HOST,'cyberdat'] and str(identity[4])=='0','Wrong staging identity');need(original_backup.is_dir() and original_backup.stat().st_uid==0 and original_backup.stat().st_mode&0o077==0,'Original backup unavailable')
 saved=json.loads((original_backup/'state.json').read_text());need(saved['page_id']==61 and module.page_info()['id']==61,'Staging page identity changed')
 need(module.sha(original_backup/'theme.tar.gz')==saved['theme_sha256'] and module.sha(original_backup/'staging.sql.gz')==saved['sql_sha256'],'Original backup checksum mismatch')
 protected=module.guards();research=module.research_code();timer_hashes=module.timer_fingerprints()
 code="require_once ABSPATH.'wp-admin/includes/plugin.php';global $wpdb;$k='rank_math_registration_skip';echo wp_json_encode(['rank_math_active'=>is_plugin_active('seo-by-rank-math/rank-math.php'),'helper_available'=>class_exists('RankMath\\\\Helper'),'registration_invalid'=>class_exists('RankMath\\\\Helper')?\\RankMath\\Helper::is_invalid_registration():null,'skip_exists'=>(bool)$wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM '.$wpdb->options.' WHERE option_name=%s',$k)),'skip_value'=>get_option($k,null),'constant_skip'=>defined('RANK_MATH_REGISTRATION_SKIP')?(bool)RANK_MATH_REGISTRATION_SKIP:null]);"
 # PHP namespace in class_exists is data, not executable untrusted input.
 state=json.loads(module.wp('eval',code).stdout)
 print('RANK MATH STATE: '+json.dumps(state),flush=True)
 required=repair_needed(state)
 basic=getpass.getpass('EXISTING staging HTTP Basic Auth password (hidden): ');need(basic and module.fetch('/threat-intelligence/',basic)[0]==200,'Basic Auth check failed')
 if required:
  phase='private staging backup before supported free-mode option update'
  parent=module.BACKUPS;need(parent.is_dir() and parent.stat().st_uid==0 and parent.stat().st_mode&0o077==0,'Unsafe backup parent')
  stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ');repair_backup=parent/('rankmath-free-'+stamp);repair_backup.mkdir(mode=0o700)
  module.database_backup(repair_backup/'staging.sql.gz')
  (repair_backup/'state.json').write_text(json.dumps({'option_name':'rank_math_registration_skip','previous':state,'sql_sha256':module.sha(repair_backup/'staging.sql.gz'),'original_deploy_backup':str(original_backup)}))
  print('REPAIR BACKUP: '+str(repair_backup),flush=True)
  phase='enable standard Skip registration mode, no account connection'
  module.wp('eval',"require_once ABSPATH.'wp-admin/includes/plugin.php';if(!class_exists('RankMath\\\\Helper')||!\\RankMath\\Helper::is_invalid_registration()||get_option('rank_math_registration_skip')){throw new RuntimeException('State changed; no write');}update_option('rank_math_registration_skip',true,false);")
  after=json.loads(module.wp('eval',code).stdout);need(after['skip_value'] and after['registration_invalid'] is False,'Supported skip did not enable free frontend; no further settings changed')
  (repair_backup/'COMPLETE').write_text('COMPLETE\n');print('PASS: confirmed registration gate; official free no-account Skip option applied. No subscription, account, token, plugin code or SEO tag added.',flush=True)
 else:
  print('INFO: registration is already valid; no option update performed',flush=True)
 phase='fresh HTTPS Rank Math output and remaining application checks'
 status,headers,body=module.fetch('/threat-intelligence/',basic);need(status==200 and 'noindex' in headers.get('X-Robots-Tag',''),'HTTP/noindex regression')
 module.verify_description(body.decode('utf-8','replace'))
 need(protected==module.guards() and research==module.research_code() and timer_hashes==module.timer_fingerprints(),'Protected state changed')
 # Release our lock before the existing verifier acquires the same lock.
 fcntl.flock(lock,fcntl.LOCK_UN);lock.close()
 # Reuse hidden Basic Auth input in memory; only the real WP login password is asked next.
 original_getpass=module.getpass.getpass
 def hidden(prompt,*a,**kw):
  if prompt.startswith('EXISTING staging HTTP Basic Auth'):return basic
  return original_getpass(prompt,*a,**kw)
 module.getpass.getpass=hidden
 sys.argv=[str(B/'deploy-threat-2.py'),'--verify',str(original_backup)]
 try:module.main()
 finally:module.getpass.getpass=original_getpass
 print('PASS: Threat Intelligence verification finished; Rank Math owns SEO output. Production, Research Agent and timers unchanged.')

if __name__=='__main__':
 try:main()
 except BaseException as error:
  print('BLOCKED: phase='+phase);print('Error type: '+type(error).__name__)
  if isinstance(error,RuntimeError):print('Reason: '+str(error))
  if repair_backup:print('REPAIR BACKUP: '+str(repair_backup))
  print('No raw credentials, registration account data or API responses printed. Do not reinstall or rerun --apply.');sys.exit(1)
