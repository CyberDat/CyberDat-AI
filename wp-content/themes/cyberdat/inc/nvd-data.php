<?php
/** Bounded, development-only NVD enrichment for existing KEV IDs. No public routes. */
defined('ABSPATH') || exit;
function cyberdat_nvd_id($id){return is_string($id) && (bool)preg_match('/^CVE-\d{4}-\d{4,19}$/D',$id);}
function cyberdat_nvd_url($id){return cyberdat_nvd_id($id)?'https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds='.rawurlencode($id):false;}
function cyberdat_nvd_live_enabled(){return cyberdat_kev_development() && !(defined('CYBERDAT_PLAYGROUND') && CYBERDAT_PLAYGROUND) && defined('CYBERDAT_NVD_LIVE') && CYBERDAT_NVD_LIVE===true;}
function cyberdat_nvd_key(){
 $key=getenv('CYBERDAT_NVD_API_KEY');
 return is_string($key) && preg_match('/^[A-Za-z0-9-]{1,256}$/D',$key)?$key:'';
}
/** Higher version, NIST source, Primary, source/vector lexical order. Never highest score. */
function cyberdat_nvd_parse($json,$id){
 if(!cyberdat_nvd_id($id) || !is_string($json) || strlen($json)>1048576){return new WP_Error('nvd_input','Invalid input or response size.');}
 try{$data=json_decode($json,true,48,JSON_THROW_ON_ERROR);}catch(Throwable $e){return new WP_Error('nvd_json','Invalid JSON.');}
 if(!is_array($data) || ($data['version']??'')!=='2.0' || !isset($data['totalResults'],$data['vulnerabilities']) || !is_int($data['totalResults']) || !is_array($data['vulnerabilities']) || !array_is_list($data['vulnerabilities'])){return new WP_Error('nvd_structure','Invalid NVD envelope.');}
 if($data['totalResults']===0 && $data['vulnerabilities']===[]){return new WP_Error('nvd_not_found','Not available from NVD; vulnerability existence is not disproven.');}
 if($data['totalResults']!==1 || count($data['vulnerabilities'])!==1 || ($data['startIndex']??0)!==0){return new WP_Error('nvd_structure','Expected one specific CVE.');}
 $cve=$data['vulnerabilities'][0]['cve']??null;
 if(!is_array($cve) || ($cve['id']??'')!==$id || !isset($cve['descriptions']) || !is_array($cve['descriptions']) || !is_array($cve['metrics']??[])){return new WP_Error('nvd_cve','Mismatched CVE or malformed record.');}
 if(($cve['vulnStatus']??'')==='Rejected'){return new WP_Error('nvd_rejected','NVD record rejected; retain KEV context.');}
 $descriptions=[];foreach($cve['descriptions'] as $d){if(!is_array($d) || !isset($d['lang'],$d['value']) || !is_string($d['value']) || strlen($d['value'])>16384){return new WP_Error('nvd_description','Invalid description.');}if($d['lang']==='en'){$descriptions[]=$d['value'];}}sort($descriptions,SORT_STRING);
 $choice=null;
 foreach(['cvssMetricV40'=>'4.0','cvssMetricV31'=>'3.1','cvssMetricV30'=>'3.0','cvssMetricV2'=>'2.0'] as $key=>$version){
  if(!isset($cve['metrics'][$key])){continue;}
  $list=$cve['metrics'][$key];if(!is_array($list) || !array_is_list($list) || count($list)>128){return new WP_Error('nvd_metric','Invalid metrics.');}
  $valid=[];
  foreach($list as $metric){
   $cv=$metric['cvssData']??[];$score=$cv['baseScore']??null;$source=$metric['source']??null;$type=$metric['type']??null;$vector=$cv['vectorString']??null;
   if(($cv['version']??'')!==$version || (!is_float($score) && !is_int($score)) || !is_finite((float)$score) || $score<0 || $score>10 || abs($score*10-round($score*10))>0.000001 || !is_string($source) || trim($source)==='' || strlen($source)>256 || !in_array($type,['Primary','Secondary'],true) || !is_string($vector) || strlen($vector)>1024 || !preg_match($version==='2.0'?'~^AV:[A-Z]/~D':'~^CVSS:'.preg_quote($version,'~').'/~D',$vector)){return new WP_Error('nvd_metric','Invalid CVSS assessment.');}
   $severity='Unclassified';$raw=$cv['baseSeverity']??($version==='2.0'?($metric['baseSeverity']??null):null);
   if($raw!==null && !in_array($raw,['NONE','LOW','MEDIUM','HIGH','CRITICAL'],true)){return new WP_Error('nvd_metric','Invalid severity.');}
   if($version!=='2.0' && $raw!==null){
    $expected=$score===0 || $score===0.0?'NONE':($score<4?'LOW':($score<7?'MEDIUM':($score<9?'HIGH':'CRITICAL')));
    if($raw!==$expected){return new WP_Error('nvd_metric','Inconsistent score/severity.');}
    if($raw!=='NONE'){$severity=ucfirst(strtolower($raw));}
   }
   $valid[]=['version'=>$version,'score'=>(float)$score,'severity'=>$severity,'source'=>$source,'type'=>$type,'vector'=>$vector,'legacy_severity'=>$version==='2.0'?$raw:null];
  }
  usort($valid,static function($a,$b){return ((strtolower($a['source'])==='nvd@nist.gov'?0:1) <=> (strtolower($b['source'])==='nvd@nist.gov'?0:1)) ?: (($a['type']==='Primary'?0:1) <=> ($b['type']==='Primary'?0:1)) ?: strcmp(strtolower($a['source']),strtolower($b['source'])) ?: strcmp($a['source'],$b['source']) ?: strcmp($a['vector'],$b['vector']) ?: ($a['score']<=>$b['score']);});
  if($choice===null && $valid){$choice=$valid[0];}
 }
 return ['id'=>$id,'description'=>$descriptions[0]??'','assessment'=>$choice];
}
function cyberdat_nvd_catalog(){
 if(!cyberdat_kev_development()){return [];}
 $cache=get_option('cyberdat_kev_last_good');return is_array($cache)?($cache['catalog']['vulnerabilities']??[]):[];
}
function cyberdat_nvd_allowed(){return array_slice(array_values(array_filter(cyberdat_nvd_catalog(),static fn($r)=>cyberdat_nvd_id($r['cveID']??null))),0,2000);}
function cyberdat_nvd_option($id){return 'cyberdat_nvd_cve_'.$id;}
function cyberdat_nvd_index(){ $index=get_option('cyberdat_nvd_index',[]);return is_array($index)?$index:[]; }
/** Only this module's bounded cache is pruned; no schema/table changes. */
function cyberdat_nvd_reconcile($index){
 $allowed=array_fill_keys(array_column(cyberdat_nvd_allowed(),'cveID'),true);
 foreach($index as $id=>$meta){if(!isset($allowed[$id])){delete_option(cyberdat_nvd_option($id));unset($index[$id]);}}
 return $index;
}
function cyberdat_nvd_store($record,$at,$snapshot=false){
 $id=$record['id']??null;
 if(!cyberdat_kev_development() || !cyberdat_nvd_id($id) || !in_array($id,array_column(cyberdat_nvd_allowed(),'cveID'),true)){return false;}
 $value=['schema'=>1,'record'=>$record,'checked_at'=>(int)$at,'snapshot'=>(bool)$snapshot];$option=cyberdat_nvd_option($id);
 if(!update_option($option,$value,false) && get_option($option)!==$value){return false;}
 $index=cyberdat_nvd_reconcile(cyberdat_nvd_index());$a=$record['assessment'];
 $index[$id]=['checked_at'=>(int)$at,'severity'=>$a?$a['severity']:'Not rated','snapshot'=>(bool)$snapshot,'error'=>'','failures'=>0,'next_retry'=>0];
 return update_option('cyberdat_nvd_index',$index,false) || cyberdat_nvd_index()===$index;
}
function cyberdat_nvd_view($id,$now=null){
 $now=$now??time();if(!cyberdat_kev_development() || !cyberdat_nvd_id($id)){return null;}
 $cache=get_option(cyberdat_nvd_option($id));if(!is_array($cache) || ($cache['schema']??0)!==1 || ($cache['record']['id']??'')!==$id){return null;}
 $meta=cyberdat_nvd_index()[$id]??[];
 $cache['status']=$cache['snapshot'] || $cache['checked_at']>$now || $now-$cache['checked_at']>604800 || !empty($meta['error'])?'Stale':'Fresh';return $cache;
}
/** Summary avoids reading every individual record on a homepage request. */
function cyberdat_nvd_coverage(){
 $all=array_fill_keys(array_column(cyberdat_nvd_catalog(),'cveID'),true);$index=cyberdat_nvd_index();$counts=['Critical'=>0,'High'=>0,'Medium'=>0,'Low'=>0,'Unrated / Unclassified'=>0];$loaded=0;$snapshots=0;$stale=0;
 foreach($index as $id=>$m){if(!isset($all[$id]) || empty($m['checked_at'])){continue;}++$loaded;if(!empty($m['snapshot'])){++$snapshots;}if(!empty($m['snapshot']) || time()-$m['checked_at']>604800 || !empty($m['error'])){++$stale;}$label=isset($counts[$m['severity']??''])?$m['severity']:'Unrated / Unclassified';++$counts[$label];}
 return ['loaded'=>$loaded,'total'=>count($all),'counts'=>$counts,'snapshots'=>$snapshots,'stale'=>$stale];
}
function cyberdat_nvd_next($index,$now){
 $eligible=[];foreach(cyberdat_nvd_allowed() as $r){$id=$r['cveID'];$m=$index[$id]??[];
  if(($m['next_retry']??0)>$now || (!empty($m['checked_at']) && empty($m['snapshot']) && $now-$m['checked_at']<604800)){continue;}
  $eligible[]=['id'=>$id,'new'=>(empty($m['checked_at']) || !empty($m['snapshot']))?0:1,'checked'=>$m['checked_at']??0,'date'=>$r['dateAdded']];
 }
 usort($eligible,static fn($a,$b)=>($a['new']<=>$b['new']) ?: ($a['new']===1?($a['checked']<=>$b['checked']):0) ?: strcmp($b['date'],$a['date']) ?: strcmp($b['id'],$a['id']));return $eligible[0]['id']??null;
}
function cyberdat_nvd_unlock($lock){global $wpdb;$deleted=$wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->options} WHERE option_name = %s AND option_value = %s",'cyberdat_nvd_lock',maybe_serialize($lock)));if($deleted){wp_cache_delete('cyberdat_nvd_lock','options');wp_cache_delete('notoptions','options');}return (bool)$deleted;}
function cyberdat_nvd_lock($now){$lock=['token'=>wp_generate_uuid4(),'expires'=>$now+120];if(add_option('cyberdat_nvd_lock',$lock,'',false)){return $lock;}$old=get_option('cyberdat_nvd_lock');if(is_array($old) && ($old['expires']??PHP_INT_MAX)<$now && cyberdat_nvd_unlock($old) && add_option('cyberdat_nvd_lock',$lock,'',false)){return $lock;}return false;}
function cyberdat_nvd_retry_after($header,$now){$header=trim((string)$header);if(preg_match('/^\d{1,10}$/D',$header)){return (int)$header;}if(strlen($header)<100){$stamp=strtotime($header);if($stamp!==false){return max(0,$stamp-$now);}}return 0;}
/** One request maximum. Explicit tests intercept HTTP; Cron requires live opt-in. */
function cyberdat_nvd_worker(){
 if(!cyberdat_kev_development()){return new WP_Error('nvd_disabled','Development only.');}
 $now=time();$lock=cyberdat_nvd_lock($now);if(!$lock){return new WP_Error('nvd_locked','Worker already running.');}
 try{
  $runtime=get_option('cyberdat_nvd_runtime',[]);if(($runtime['next_run']??0)>$now){return new WP_Error('nvd_cooldown','Background cooldown.');}
  $index=cyberdat_nvd_reconcile(cyberdat_nvd_index());update_option('cyberdat_nvd_index',$index,false);$id=cyberdat_nvd_next($index,$now);if(!$id){return true;}
  update_option('cyberdat_nvd_runtime',['next_run'=>$now+60],false);
  $headers=['Accept'=>'application/json'];$key=cyberdat_nvd_key();if($key!==''){$headers['apiKey']=$key;}
  $response=wp_safe_remote_get(cyberdat_nvd_url($id),['timeout'=>10,'redirection'=>0,'sslverify'=>true,'reject_unsafe_urls'=>true,'limit_response_size'=>1048577,'headers'=>$headers,'user-agent'=>'CyberDat-NVD/0.5']);
  $retry=0;$code=is_wp_error($response)?0:(int)wp_remote_retrieve_response_code($response);
  if(is_wp_error($response)){$record=new WP_Error('nvd_transport','Transport failed.');}
  elseif($code!==200){$record=new WP_Error('nvd_http_'.$code,'NVD request failed.');$retry=cyberdat_nvd_retry_after(wp_remote_retrieve_header($response,'retry-after'),$now);}
  elseif(!preg_match('~^application/json(?:\s*;|$)~i',(string)wp_remote_retrieve_header($response,'content-type'))){$record=new WP_Error('nvd_content_type','Unexpected response.');}
  else{$record=cyberdat_nvd_parse(wp_remote_retrieve_body($response),$id);}
  if(get_option('cyberdat_nvd_lock')!==$lock || time()>=$lock['expires']){return new WP_Error('nvd_lock_lost','Lease expired.');}
  if(!is_wp_error($record)){
   if(!cyberdat_nvd_store($record,$now)){return new WP_Error('nvd_cache_write','Cannot save verified data.');}
   return true;
  }
  $meta=$index[$id]??[];$fails=min(9,($meta['failures']??0)+1);$backoff=min(86400,300*(2**($fails-1)));
  if(in_array($code,[403,429],true)){$backoff=max(900,$backoff);}
  if(in_array($code,[404],true) || $record->get_error_code()==='nvd_not_found'){$backoff=max(86400,$backoff);}
  $backoff=max($backoff,$retry);$meta['failures']=$fails;$meta['error']=$record->get_error_code();$meta['next_retry']=$now+$backoff;$index[$id]=$meta;
  $global_delay=($code===404 || $record->get_error_code()==='nvd_not_found')?max(60,$retry):$backoff;
  update_option('cyberdat_nvd_index',$index,false);update_option('cyberdat_nvd_runtime',['next_run'=>$now+$global_delay],false);
  return $record;
 }finally{cyberdat_nvd_unlock($lock);}
}
function cyberdat_nvd_intervals($schedules){$schedules['cyberdat_nvd_minute']=['interval'=>60,'display'=>__('CyberDat NVD queue','cyberdat')];return $schedules;}
function cyberdat_nvd_schedule(){if(cyberdat_nvd_live_enabled()){if(!wp_next_scheduled('cyberdat_nvd_update')){wp_schedule_event(time()+60,'cyberdat_nvd_minute','cyberdat_nvd_update');}}elseif(wp_next_scheduled('cyberdat_nvd_update')){wp_clear_scheduled_hook('cyberdat_nvd_update');}}
function cyberdat_nvd_cron(){if(cyberdat_nvd_live_enabled()){cyberdat_nvd_worker();}}
function cyberdat_nvd_stop(){wp_clear_scheduled_hook('cyberdat_nvd_update');}
add_filter('cron_schedules','cyberdat_nvd_intervals');add_action('init','cyberdat_nvd_schedule');add_action('cyberdat_nvd_update','cyberdat_nvd_cron');add_action('switch_theme','cyberdat_nvd_stop');
