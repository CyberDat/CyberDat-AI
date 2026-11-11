#!/usr/bin/env python3
import sys,os,pathlib,importlib.util,json,hashlib,datetime,getpass,re,base64,urllib.request,urllib.error
sys.dont_write_bytecode=True
P=pathlib.Path;D=P(__file__).parent;B=P('/var/backups/cyberdat-staging/research-0.8.3-20261111T170009Z')
spec=importlib.util.spec_from_file_location('support',D.parent/'content-0.9.0-prepared/support.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
os.umask(0o077);os.chdir(m.RUNTIME)
report={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
release=json.loads((B/'release.json').read_text());m.need(m.research_code()==release['research'],'Installed Research release hash mismatch');m.need(m.sha(m.THEME/'template-parts/home/threat-dashboard.php')==release['theme_sha256'],'Installed template hash mismatch')
# Exact launcher cwd, global config and open_basedir; evaluate only read-only state.
r=m.wp('eval',"echo wp_json_encode(['staging'=>cdra_staging(),'version'=>'0.8.3','content_stage'=>cdca_stage(),'open_basedir'=>ini_get('open_basedir')]);",check=False)
m.need(r.returncode==0 and b'open_basedir restriction' not in r.stderr+b'' and not re.search(rb'PHP (?:Warning|Notice|Fatal|Parse)',r.stderr),'WP-CLI runtime warning remains');report['wp_cli_warning_free']=True;print('PASS: WP-CLI exact service working directory/open_basedir, no warnings',flush=True)
os.chdir(m.RUNTIME)
code=r"""
$s=new CDRA_Store();global $wpdb;$lock='cdra_'.substr(hash('sha256',DB_NAME.$s->prefix),0,32);cdra_need((int)$wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s,60)',$lock))===1,'verification_lock');
try{
 $wpdb->query('SET TRANSACTION READ ONLY');$wpdb->query('START TRANSACTION WITH CONSISTENT SNAPSHOT');
 $d=cyberdat_research_dashboard();$sql=$wpdb->get_results("SELECT severity,COUNT(*) n FROM stg_cdra_items WHERE active=1 AND source='nvd' GROUP BY severity",ARRAY_A);$severity=array_fill_keys(['Critical','High','Medium','Low','None','Unrated'],0);foreach($sql as $r){$key=$r['severity']==='Not rated'?'Unrated':$r['severity'];$severity[$key]=(int)$r['n'];}
 $n=(int)$wpdb->get_var("SELECT COUNT(*) FROM stg_cdra_items WHERE source='nvd' AND active=1");$k=(int)$wpdb->get_var("SELECT COUNT(*) FROM stg_cdra_items WHERE source='kev' AND active=1");
 cdra_need($d['counts']['nvd']===$n&&$d['counts']['kev']===$k&&$d['severity']===$severity,'projection_sql');$feedok=true;$received=0;foreach($d['feed'] as $r){$real=$wpdb->get_row($wpdb->prepare('SELECT published,first_seen FROM stg_cdra_items WHERE source=%s AND source_id=%s LIMIT 1',$r['source'],$r['id']),ARRAY_A);$feedok=$feedok&&$real&&$real['published']===$r['published'];if(isset($r['received_at'])){$received++;$feedok=$feedok&&$r['received_at']===$real['first_seen'];}}cdra_need($feedok,'feed_dates_sql');
 $cp=$s->get('nvd_checkpoint');$w=$s->get('nvd_window');$completed=$s->get('nvd_last_completed_window');$proof=$w['time_proof']??($completed['time_proof']??null);$missing=0;if($proof){foreach(cdra_nvd_certified_ids($proof['segments']) as $id){if(!$wpdb->get_var($wpdb->prepare("SELECT id FROM stg_cdra_items WHERE source='nvd' AND source_id=%s",$id))){$missing++;}}}
 $dup=(int)$wpdb->get_var('SELECT COUNT(*) FROM (SELECT source,source_key FROM stg_cdra_items GROUP BY source,source_key HAVING COUNT(*)>1) x');cdra_need(!$missing&&!$dup,'proof_identifiers');
 $jobs=$wpdb->get_results('SELECT status,is_test,COUNT(*) n FROM stg_cdca_jobs GROUP BY status,is_test',ARRAY_A);$content=hash('sha256',cdca_json([$wpdb->get_results('SELECT * FROM stg_cdca_jobs ORDER BY id',ARRAY_A),$wpdb->get_results('SELECT * FROM stg_cdca_versions ORDER BY id',ARRAY_A),$wpdb->get_results('SELECT * FROM stg_cdca_enrichments ORDER BY id',ARRAY_A),$wpdb->get_results('SELECT * FROM stg_cdca_evidence ORDER BY id',ARRAY_A)]));
 $u=get_user_by('login','cyberdat_staging_admin');$active=(array)get_option('active_plugins');$mfa=array_values(array_filter($active,static fn($v)=>str_contains($v,'two-factor')||str_contains($v,'two_factor')||str_contains($v,'wordfence')||str_contains($v,'login-security')));$umeta=$u?$wpdb->get_col($wpdb->prepare("SELECT meta_key FROM {$wpdb->usermeta} WHERE user_id=%d AND (meta_key LIKE '%%two_factor%%' OR meta_key LIKE '%%2fa%%' OR meta_key LIKE '%%totp%%')",$u->ID)):[];
 echo wp_json_encode(['counts'=>$d['counts'],'severity'=>$severity,'generated_at'=>$d['generated_at'],'checkpoint'=>$cp,'window'=>cdra_nvd_progress_view($w),'completed'=>cdra_nvd_progress_view($completed),'missing_certified_ids'=>$missing,'duplicate_ids'=>$dup,'dashboard_sql_match'=>true,'feed_publication_matches'=>true,'feed_receipt_rows'=>$received,'feed_count'=>count($d['feed']),'content_queue'=>$jobs,'content_rows_sha256'=>$content,'posts'=>(int)$wpdb->get_var('SELECT COUNT(*) FROM stg_posts'),'content_enrichment_tables'=>true,'mfa_plugins'=>$mfa,'admin_mfa_metadata_keys'=>$umeta,'blog_public'=>get_option('blog_public')]);
 $wpdb->query('ROLLBACK');
}finally{$wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)',$lock));}
"""
r=m.wp('eval',code,check=False)
if r.returncode:
 print('BLOCKED: SQL/application verification',flush=True)
 print(json.dumps(re.findall(r'(?:PHP Fatal error:|Uncaught [A-Za-z_\\]+:)[^\n]*',r.stderr.decode(errors='replace'))));sys.exit(1)
report['sql']=json.loads(r.stdout);m.need(report['sql']['feed_receipt_rows']==report['sql']['feed_count'],'Receipt projection not yet rebuilt by a scheduled cycle');print('PASS: projection, publication/receipt, certified IDs and Content queue checked',flush=True)
# One diagnostic fetch through the installed secure client, no ingestion or health/checkpoint write.
code="try{$r=(new CDRA_Client())->get('sophos');echo wp_json_encode(['status'=>$r['status'],'diagnostic'=>$r['diagnostic'],'rows'=>count(cdra_discovery_parse('sophos',$r['body']))]);}catch(CDRA_Error $e){echo wp_json_encode(['error'=>$e->getMessage(),'diagnostic'=>$e->diagnostic]);}"
r=m.wp('eval',code,check=False);m.need(r.returncode==0,'Sophos diagnostic failed');report['sophos_probe']=json.loads(r.stdout);print('SOPHOS DIAGNOSTIC',json.dumps(report['sophos_probe']),flush=True)
basic=getpass.getpass('EXISTING staging HTTP Basic Auth password (hidden): ')
status,h,body=m.fetch('/threat-intelligence/',basic);m.need(status==200,'Staging Basic Auth rejected')
text=body.decode('utf-8','replace');m.need('Latest 12 published entries from configured sources' in text and 'Latest 6 published advisories from configured sources' in text and 'NVD last successful sync:' in text,'Freshness labels missing');m.need('noindex' in h.get('X-Robots-Tag',''),'Noindex missing');m.need(text.count('data-chart-id=')==6,'Dashboard charts missing');report['http']={'dashboard':status,'charts':6,'freshness_labels':True,'noindex':True,'anonymous':m.fetch('/threat-intelligence/')[0]};m.need(report['http']['anonymous']==401,'Basic Auth not enforced')
status,_,body=m.fetch('/',basic);m.need(status==200 and b'data-threat-pulse="2.1"' in body,'Threat Pulse regression');report['http']['home']=status;report['http']['pulse_2_1']=True
for query in ['ti_source=cert-eu','ti_kind=advisory','ti_severity=Critical&ti_kind=cve']:
 m.need(m.fetch('/threat-intelligence/?'+query,basic)[0]==200,'Filter regression')
report['http']['filters']=True
# No login or MFA bypass: gated admin pages should redirect to authentication.
for path in ['/wp-admin/admin.php?page=cyberdat-research','/wp-admin/admin.php?page=cyberdat-content']:
 st,_,b=m.fetch(path,basic);m.need(st==200 and b'user_login' in b,'Unauthenticated admin boundary regression')
report['http']['admin_login_boundary']=True;report['mfa_actual_otp']='UNVERIFIED';report['browser_visual_js_console']='UNVERIFIED'
(B/'verification.json').write_text(json.dumps(report,indent=2));print('VERIFICATION',json.dumps(report));print('PASS: staging HTTP, auth/noindex, dashboard/pulse/filter and admin login boundaries; actual OTP/browser interaction remains UNVERIFIED')
