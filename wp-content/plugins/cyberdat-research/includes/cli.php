<?php
defined('ABSPATH') || exit;
/** Fair due-time selection; interval/backoff ownership remains in CDRA_Service. */
function cdra_dispatch_due_source($store,$now=null){
 $now=$now??time();$due=[];
 foreach(cdra_sources()+cdra_discovery_registry() as $id=>$spec){
  $legacy=isset(cdra_sources()[$id]);if(!$legacy&&!cdra_discovery_enabled($id,$store)){continue;}
  $h=$store->get('health:'.$id,[]);if($legacy&&empty($h['last_success'])){continue;}
  if($legacy&&!empty($h['last_error'])&&($h['failures']??0)>=6){continue;}
  $at=(int)($h['next_due']??($legacy?PHP_INT_MAX:0));if($at>$now){continue;}
  $due[$id]=$at;
 }
 if(!$due){return null;}asort($due,SORT_NUMERIC);return array_key_first($due);
}
class CDRA_CLI {
 /** Install only additive discovery tables, never from page requests. */
 public function discovery_install(){cdra_need(cdra_staging(),'staging_only');(new CDRA_Discovery_Store())->install();WP_CLI::success('Additive discovery tables ready; no import or source enabled.');}
 /** Read-only future Content Agent contract. */
 public function discovery_test(){require CDRA_DIR.'/tests/discovery-database.php';cdra_discovery_database_tests();}
 public function discovery_export(){WP_CLI::line(cdra_json(cdra_discovery_handoff()));}
 public function status(){cdra_need(cdra_staging(),'staging_only');$s=new CDRA_Store();$sources=[];foreach(cdra_sources() as $id=>$spec){$sources[$id]=(object)$s->get('health:'.$id,[]);}$data=$s->get('dashboard',[]);WP_CLI::line(cdra_json(['sources'=>$sources,'kev'=>$s->get('kev_catalog')['count']??0,'nvd'=>$s->count('nvd'),'queue'=>$s->count(),'coverage_origin'=>$s->get('nvd_origin'),'checkpoint'=>$s->get('nvd_checkpoint'),'window'=>$s->get('nvd_window'),'last_completed_window'=>$s->get('nvd_last_completed_window'),'backfill'=>$s->get('backfill',['status'=>'not_requested']),'complete_nvd'=>false,'dashboard_generation'=>$data['generated_at']??null,'live_enabled'=>$s->get('live_enabled',false)]));}
 /** Bounded Research Agent operation.
  * @synopsis [--source=<source>] [--manual] [--scheduled]
  */
 public function sync($args,$assoc){$source=$assoc['source']??'all';cdra_need($source==='all'||isset(cdra_sources()[$source])||isset(cdra_discovery_registry()[$source]),'source_not_allowed');$result=(new CDRA_Service())->sync($source,!empty($assoc['manual']));WP_CLI::line(cdra_json($result));if($result['errors']){WP_CLI::halt(1);}}
 public function enable(){cdra_need(cdra_staging(),'staging_only');$s=new CDRA_Store();$data=$s->get('dashboard');cdra_need($data&&$data['kev']['catalog']['count']>0&&$data['indexed_cves']>0&&empty($data['sources']['kev']['last_error'])&&empty($data['sources']['nvd']['last_error'])&&!empty($data['nvd_last_incremental_success']),'initial_live_verification_required');$s->put('live_enabled',true);WP_CLI::success('Unified dashboard provider enabled; legacy snapshots/workers are not used.');}
 /** Bounded Research Agent operation.
  * @synopsis --start=<date> --end=<date>
  */
 public function backfill($args,$assoc){$start=$assoc['start']??'';$end=$assoc['end']??'';cdra_need(is_string($start)&&is_string($end)&&preg_match('/^\d{4}-\d{2}-\d{2}$/D',$start)&&preg_match('/^\d{4}-\d{2}-\d{2}$/D',$end),'backfill_dates');(new CDRA_Service())->backfill(cdra_time($start.'T00:00:00Z'),cdra_time($end.'T00:00:00Z'));WP_CLI::success('Bounded backfill requested; no download in this command.');}
 public function dispatch(){
  cdra_need(cdra_staging(),'staging_only');$s=new CDRA_Store();$pending=$s->get('manual_queue',[]);
  foreach($pending as $source=>$request){cdra_need(isset(cdra_sources()[$source]),'source_not_allowed');$health=$s->get('health:'.$source,[]);if(!empty($health['last_error'])&&($health['next_due']??0)>time()){continue;}if(time()-($health['last_attempt']??0)<300){continue;}
   $s->mutate('manual_queue',static function($queue)use($source){unset($queue[$source]);return $queue;});try{$result=(new CDRA_Service($s))->sync($source,true);}catch(CDRA_Error $error){if($error->getMessage()==='ingestion_locked'){$s->mutate('manual_queue',static function($queue)use($source,$request){$queue[$source]=$queue[$source]??$request;return $queue;});}throw $error;}WP_CLI::line(cdra_json($result));return;
  }
  // Healthy jobs can be overdue when a timer fires just before next_due.
  // Select by oldest due time so NVD continuation cannot indefinitely crowd out feeds.
  $source=cdra_dispatch_due_source($s);
  if($source!==null){$result=(new CDRA_Service($s))->sync($source);$result['dispatch_source']=$source;WP_CLI::line(cdra_json($result));return;}
  $request=$s->get('backfill');if($request&&$request['status']==='active'&&($request['next_due']??0)<=time()){
   $lock='cdra_'.substr(hash('sha256',DB_NAME.$s->prefix),0,32);cdra_need((int)$s->db->get_var($s->db->prepare('SELECT GET_LOCK(%s,0)',$lock))===1,'ingestion_locked');
   try{$service=new CDRA_Service($s);$service->nvd(true);$service->projection();WP_CLI::success('One bounded backfill batch completed.');}catch(Throwable $error){$request=$s->get('backfill');$request['last_error']=$error instanceof CDRA_Error?$error->getMessage():'processing_error';$request['next_due']=time()+max(7200,$error instanceof CDRA_Error?$error->retry:0);$s->put('backfill',$request);WP_CLI::error('Backfill batch failed; last-good records and checkpoint retained.');}finally{$s->db->get_var($s->db->prepare('SELECT RELEASE_LOCK(%s)',$lock));}return;
  }
  WP_CLI::line('Idle: no due bounded manual/retry/backfill job.');
 }
 /** Bounded Research Agent operation.
  * @synopsis [--limit=<number>]
  */
 public function export($args,$assoc){WP_CLI::line(cdra_json(cdra_export_approved((int)($assoc['limit']??20))));}
 public function test(){cdra_need(cdra_staging(),'staging_only');require CDRA_DIR.'/tests/database.php';cdra_database_tests();}
 public function verify(){
  cdra_need(cdra_staging(),'staging_only');$s=new CDRA_Store();$data=$s->get('dashboard');cdra_need($s->get('live_enabled')===true&&$data&&$data['indexed_cves']>0&&$data['kev']['catalog']['count']>0,'live_data_missing');
  cdra_need(!cyberdat_kev_live_enabled()&&!cyberdat_nvd_live_enabled(),'legacy_workers_not_disabled');
  cdra_need(is_wp_error(cyberdat_kev_refresh())&&is_wp_error(cyberdat_nvd_worker()),'legacy_refresh_not_blocked');
  cdra_need(!wp_next_scheduled('cyberdat_kev_update')&&!wp_next_scheduled('cyberdat_nvd_update'),'legacy_job_present');
  cdra_need((string)get_option('blog_public')==='0'&&defined('DISABLE_WP_CRON')&&DISABLE_WP_CRON,'staging_guards');
  cdra_need(is_wp_error(wp_remote_get(cdra_sources()['kev']['url'],['timeout'=>1])),'global_http_restriction_missing');
  cdra_need(apply_filters('pre_wp_mail',null,[])===false,'mail_block_missing');
  foreach(['source,source_key','source,url_key'] as $group){cdra_need((int)$s->db->get_var("SELECT COUNT(*) FROM (SELECT $group FROM {$s->prefix}items GROUP BY $group HAVING COUNT(*)>1) duplicates")===0,'duplicates_detected');}
  cdra_need(cyberdat_kev_view()['cache']['catalog']['count']===$data['kev']['catalog']['count']&&cyberdat_nvd_coverage()['loaded']===count($data['nvd']),'dashboard_provider_mismatch');
  cdra_need($s->count()>0&&count(cdra_admin_query([]))>0,'queue_empty');
  WP_CLI::success('Unified live data, deduplication, dashboard, queue, legacy-loader exclusion and staging security verified.');
 }
}
if(defined('WP_CLI')&&WP_CLI&&class_exists('WP_CLI')){WP_CLI::add_command('cyberdat-research','CDRA_CLI');}
