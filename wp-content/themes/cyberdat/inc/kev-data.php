<?php
/** CISA KEV data service. No HTML, endpoints, credentials or request-time fetches. */
defined( 'ABSPATH' ) || exit;

function cyberdat_kev_sources() {
 return [
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json',
 ];
}
function cyberdat_kev_development() {
 return (defined('CYBERDAT_PLAYGROUND') && CYBERDAT_PLAYGROUND) || in_array(wp_get_environment_type(), ['local','development','staging'], true);
}
function cyberdat_kev_live_enabled() {
 if(function_exists('cyberdat_research_active') && cyberdat_research_active()){return false;}

 return cyberdat_kev_development() && !(defined('CYBERDAT_PLAYGROUND') && CYBERDAT_PLAYGROUND) && defined('CYBERDAT_KEV_LIVE') && CYBERDAT_KEV_LIVE === true;
}
function cyberdat_kev_day($value) {
 if (!is_string($value) || !preg_match('/^\d{4}-\d{2}-\d{2}$/D', $value)) { return false; }
 $date = DateTimeImmutable::createFromFormat('!Y-m-d', $value, new DateTimeZone('UTC'));
 return $date && $date->format('Y-m-d') === $value ? $date->getTimestamp() : false;
}
/** Strict validation of consumed fields; unneeded fields/URLs are discarded. */
function cyberdat_kev_validate($json, $now = null) {
 $now = $now ?? time();
 if (!is_string($json) || strlen($json) > 4194304) { return new WP_Error('kev_size', 'KEV response exceeds limit.'); }
 try { $data = json_decode($json, true, 32, JSON_THROW_ON_ERROR); }
 catch (Throwable $e) { return new WP_Error('kev_json', 'Invalid KEV JSON.'); }
 if (!is_array($data) || !isset($data['count'],$data['vulnerabilities'],$data['catalogVersion'],$data['dateReleased']) || !is_int($data['count']) || !is_array($data['vulnerabilities']) || !array_is_list($data['vulnerabilities']) || $data['count'] !== count($data['vulnerabilities']) || $data['count'] > 10000 || !is_string($data['catalogVersion']) || !preg_match('/^\d{4}\.\d{2}\.\d{2}$/D',$data['catalogVersion']) || cyberdat_kev_day(str_replace('.','-',$data['catalogVersion'])) === false || !is_string($data['dateReleased']) || !preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/D',$data['dateReleased'])) {
  return new WP_Error('kev_structure', 'Invalid KEV catalog structure.');
 }
 try { $released = new DateTimeImmutable($data['dateReleased']); }
 catch (Throwable $e) { return new WP_Error('kev_release', 'Invalid catalog release.'); }
 if (cyberdat_kev_day(substr($data['dateReleased'],0,10)) === false || $released->getTimestamp() > $now + 300 || $released->format('H:i:s') !== substr($data['dateReleased'],11,8)) { return new WP_Error('kev_release', 'Invalid or future catalog release.'); }
 $rows=[];$seen=[];
 foreach ($data['vulnerabilities'] as $row) {
  if (!is_array($row) || !isset($row['cveID'],$row['dateAdded']) || !is_string($row['cveID']) || !preg_match('/^CVE-\d{4}-\d{4,19}$/D',$row['cveID']) || isset($seen[$row['cveID']])) { return new WP_Error('kev_cve', 'Invalid or duplicate CVE.'); }
  $day=cyberdat_kev_day($row['dateAdded']);
  if ($day === false || $day > cyberdat_kev_day(gmdate('Y-m-d',$now)) || $day > cyberdat_kev_day($released->format('Y-m-d'))) { return new WP_Error('kev_date', 'Invalid or future dateAdded.'); }
  foreach (['vendorProject','product','vulnerabilityName'] as $key) {
   if (!isset($row[$key]) || !is_string($row[$key]) || trim($row[$key]) === '' || strlen($row[$key]) > 2048 || preg_match('/[\x00-\x08\x0b\x0c\x0e-\x1f]/',$row[$key])) { return new WP_Error('kev_text','Invalid KEV text.'); }
  }
  $ransom=$row['knownRansomwareCampaignUse'] ?? 'Not provided';
  if (!in_array($ransom,['Known','Unknown','Not provided'],true)) { return new WP_Error('kev_ransomware','Unknown ransomware field value.'); }
  $rows[]=['cveID'=>$row['cveID'],'vendorProject'=>$row['vendorProject'],'product'=>$row['product'],'vulnerabilityName'=>$row['vulnerabilityName'],'dateAdded'=>$row['dateAdded'],'knownRansomwareCampaignUse'=>$ransom];
  $seen[$row['cveID']]=true;
 }
 usort($rows,static function($a,$b){return strcmp($b['dateAdded'],$a['dateAdded']) ?: strcmp($b['cveID'],$a['cveID']);});
 return ['catalogVersion'=>$data['catalogVersion'],'dateReleased'=>$data['dateReleased'],'count'=>count($rows),'vulnerabilities'=>$rows];
}
/** Calendar windows: UTC reference day plus previous 6 / 29 days, inclusive. */
function cyberdat_kev_metrics($catalog, $now = null) {
 $now=$now ?? time();$today=cyberdat_kev_day(gmdate('Y-m-d',$now));$seven=0;$thirty=0;$ransom=0;$days=[];
 for($i=6;$i>=0;--$i){$days[gmdate('Y-m-d',$today-$i*86400)]=0;}
 foreach($catalog['vulnerabilities'] as $row){
  $day=cyberdat_kev_day($row['dateAdded']);
  if($day<=$today && $day>=$today-6*86400){++$seven;++$days[$row['dateAdded']];}
  if($day<=$today && $day>=$today-29*86400){++$thirty;}
  if($row['knownRansomwareCampaignUse']==='Known'){++$ransom;}
 }
 return ['total'=>$catalog['count'],'seven'=>$seven,'thirty'=>$thirty,'ransomware'=>$ransom,'days'=>$days];
}
/** Persistent last-good data: intentionally no transient expiry or autoload. */
function cyberdat_kev_store($catalog, $source, $at, $snapshot = false) {
 if (!cyberdat_kev_development() || !in_array($source,cyberdat_kev_sources(),true)) { return false; }
 $value=['schema'=>1,'catalog'=>$catalog,'source'=>$source,'fetched_at'=>(int)$at,'snapshot'=>(bool)$snapshot];
 return update_option('cyberdat_kev_last_good',$value,false) || get_option('cyberdat_kev_last_good') === $value;
}
function cyberdat_kev_view($now = null) {
 if(function_exists('cyberdat_research_active') && cyberdat_research_active()){return cyberdat_research_kev_view($now);}
 $now=$now ?? time();$cache=cyberdat_kev_development()?get_option('cyberdat_kev_last_good'):false;
 if (!is_array($cache) || ($cache['schema'] ?? 0)!==1 || !isset($cache['catalog']['vulnerabilities'],$cache['fetched_at'],$cache['source'],$cache['snapshot']) || !in_array($cache['source'],cyberdat_kev_sources(),true)) { return ['status'=>'Unavailable','cache'=>null,'metrics'=>null]; }
 $attempt=get_option('cyberdat_kev_attempt',[]);
 $stale=$cache['snapshot'] || $cache['fetched_at']>$now || $now-$cache['fetched_at']>86400 || (!empty($attempt['error']) && ($attempt['at'] ?? 0)>=$cache['fetched_at']);
 $reference=$cache['snapshot']?$cache['fetched_at']:$now;
 return ['status'=>$stale?'Stale':'Fresh','cache'=>$cache,'metrics'=>cyberdat_kev_metrics($cache['catalog'],$reference),'reference'=>$reference];
}
/** Atomic compare-and-delete prevents stale owners from deleting newer locks. */
function cyberdat_kev_unlock($lock) {
 global $wpdb;
 $deleted=$wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->options} WHERE option_name = %s AND option_value = %s",'cyberdat_kev_lock',maybe_serialize($lock)));
 if($deleted){wp_cache_delete('cyberdat_kev_lock','options');wp_cache_delete('notoptions','options');}
 return (bool)$deleted;
}
function cyberdat_kev_lock($now) {
 $lock=['token'=>wp_generate_uuid4(),'expires'=>$now+120];
 if(add_option('cyberdat_kev_lock',$lock,'',false)){return $lock;}
 $old=get_option('cyberdat_kev_lock');
 if(is_array($old) && isset($old['expires']) && $old['expires']<$now && cyberdat_kev_unlock($old) && add_option('cyberdat_kev_lock',$lock,'',false)){return $lock;}
 return false;
}
/** Internal service. Tests intercept WP HTTP; no route or public refresh action. */
function cyberdat_kev_refresh() {
 if(function_exists('cyberdat_research_active') && cyberdat_research_active()){return new WP_Error('kev_unified','Unified Research pipeline owns ingestion.');}
 if(!cyberdat_kev_development()){return new WP_Error('kev_disabled','Development only.');}
 $now=time();$lock=cyberdat_kev_lock($now);
 if(!$lock){return new WP_Error('kev_locked','Refresh already running.');}
 try{
  $attempt=get_option('cyberdat_kev_attempt',[]);
  if(isset($attempt['at']) && $now-$attempt['at']<3600){return new WP_Error('kev_throttled','Refresh cooldown.');}
  update_option('cyberdat_kev_attempt',['at'=>$now,'error'=>'in_progress'],false);
  $error='kev_http';
  foreach(cyberdat_kev_sources() as $url){
   $response=wp_safe_remote_get($url,['timeout'=>8,'redirection'=>0,'sslverify'=>true,'reject_unsafe_urls'=>true,'limit_response_size'=>4194305,'headers'=>['Accept'=>'application/json'],'user-agent'=>'CyberDat-KEV/0.5']);
   if(is_wp_error($response)){ $error='kev_transport';continue; }
   if(wp_remote_retrieve_response_code($response)!==200){$error='kev_http';continue;}
   $type=strtolower((string)wp_remote_retrieve_header($response,'content-type'));
   if(!preg_match('~^(application/json|text/plain)(?:\s*;|$)~',$type)){$error='kev_content_type';continue;}
   $catalog=cyberdat_kev_validate(wp_remote_retrieve_body($response),$now);
   if(is_wp_error($catalog)){$error=$catalog->get_error_code();continue;}
   $old=get_option('cyberdat_kev_last_good');
   if(is_array($old) && !empty($old['catalog']['count']) && $catalog['count']===0){$error='kev_empty_replacement';continue;}
   if(is_array($old) && isset($old['catalog']['dateReleased']) && (new DateTimeImmutable($catalog['dateReleased'])) < (new DateTimeImmutable($old['catalog']['dateReleased']))){$error='kev_rollback';continue;}
   if(get_option('cyberdat_kev_lock')!==$lock || time()>=$lock['expires']){$error='kev_lock_lost';break;}
   if(!cyberdat_kev_store($catalog,$url,$now)){$error='kev_cache_write';break;}
   update_option('cyberdat_kev_attempt',['at'=>$now,'error'=>''],false);
   return true;
  }
  update_option('cyberdat_kev_attempt',['at'=>$now,'error'=>$error],false);
  return new WP_Error($error,'KEV refresh failed; last verified catalog retained.');
 } finally {cyberdat_kev_unlock($lock);}
}
function cyberdat_kev_schedule() {
 if(cyberdat_kev_live_enabled() && !wp_next_scheduled('cyberdat_kev_update')){wp_schedule_event(time()+60,'twicedaily','cyberdat_kev_update');}
 elseif(!cyberdat_kev_live_enabled() && wp_next_scheduled('cyberdat_kev_update')){wp_clear_scheduled_hook('cyberdat_kev_update');}
}
function cyberdat_kev_cron(){if(cyberdat_kev_live_enabled()){cyberdat_kev_refresh();}}
function cyberdat_kev_stop(){wp_clear_scheduled_hook('cyberdat_kev_update');}
add_action('init','cyberdat_kev_schedule');
add_action('cyberdat_kev_update','cyberdat_kev_cron');
add_action('switch_theme','cyberdat_kev_stop');
