<?php
defined('ABSPATH') || exit;
class CDRA_Service {
 public $store;public $client;public $started;public $requests=0;public $pause;public $scheduled=false;public $metric_baseline=[];
 public function __construct($store=null,$client=null,$pause=null){$this->pause=$pause??'sleep';$this->store=$store??new CDRA_Store();$this->client=$client??new CDRA_Client();$this->started=microtime(true);$this->metric_baseline=$this->store->metrics??[];}
 public static function nvd_pending_due($store,$now=null){$h=$store->get('health:nvd',[]);return (bool)$store->get('nvd_window')&&($h['next_due']??0)<=($now??time())&&($h['failures']??0)<6;}
 public function request($source,$query=[],$conditional=[]){
  cdra_need(microtime(true)-$this->started<110&&$this->requests<6,'run_budget');
  if($source==='nvd'){$wait=max(0,$this->store->get('nvd_request_after',0)-time());cdra_need($wait<=35&&microtime(true)-$this->started+$wait<110,'rate_budget');if($wait){call_user_func($this->pause,$wait);}$this->store->put('nvd_request_after',time()+31);}
  $health=$this->store->get('health:'.$source,[]);$health['job']='Running';$health['last_attempt']=time();$health['last_http_status']=null;if($this->scheduled){$health['last_scheduled_attempt']=time();}$this->store->put('health:'.$source,$health);++$this->requests;$response=$this->client->get($source,$query,$conditional);$health=$this->store->get('health:'.$source,[]);$health['last_http_status']=$response['status'];$health['last_transport']=$response['diagnostic']??['kind'=>'http','http_status'=>$response['status']];$this->store->put('health:'.$source,$health);return $response;
 }
 public function success($source,$response,$received=true){
  $health=$this->store->get('health:'.$source,[]);$health['last_success']=time();$health['last_checked']=time();if($received){$health['last_received']=time();}
  $health['last_error']='';$health['next_retry']=0;$health['retry_backoff_seconds']=0;if($this->scheduled){$health['last_scheduled_success']=time();}$metric=$this->store->metrics[$source]??[];$before=$this->metric_baseline[$source]??[];$stats=[];foreach(['inserted','updated','unchanged','stale'] as $k){$stats[$k]=($metric[$k]??0)-($before[$k]??0);}if($stats['inserted']>0&&isset($metric['last_new_item'])){$health['last_new_item']=$metric['last_new_item'];}$health['last_run_stats']=$stats;$health['last_run_outcome']=$stats['inserted']>0?'received_new_items':($stats['updated']>0?'updated_existing_items':'checked_no_new_items');$health['last_run_requests']=$this->requests;if($source==='nvd'){$cp=$this->store->get('nvd_checkpoint');$health['checkpoint_age']=$cp?max(0,time()-$cp):null;}$health['failures']=0;$health['job']='Idle';$health['last_http_status']=$response['status'];if(cdra_spec($source)['format']==='rss'){$health['coverage']=!empty($response['bounded_feed_prefix'])?'first_'.(int)($response['bounded_feed_records']??25).'_complete_XML_records':'bounded_feed_document';}$health['next_due']=time()+cdra_spec($source)['interval'];
  if($source!=='nvd'){foreach(['etag'=>'etag','last-modified'=>'last_modified'] as $key=>$field){if(isset($response['headers'][$key])&&strlen($response['headers'][$key])<=512&&!preg_match('/[\r\n\x00]/',$response['headers'][$key])){$health[$field]=$response['headers'][$key];}}}
  $this->store->put('health:'.$source,$health);
 }
 public function fail($source,$error){
  $health=$this->store->get('health:'.$source,[]);$count=min(9,($health['failures']??0)+1);$delay=max($error->retry,min(86400,300*2**($count-1)),in_array($error->getMessage(),['http_403','http_429'],true)?900:0);
  $health['last_error']=$error->getMessage();$health['last_run_outcome']='error';if($error->getMessage()==='dns_failed'){$health['last_transport']=['kind'=>'dns','curl_errno'=>null,'http_status'=>null];}if($error->diagnostic){$health['last_transport']=$error->diagnostic;$health['last_http_status']=$error->diagnostic['http_status']??null;}if(preg_match('/^http_(\d{3})$/D',$error->getMessage(),$match)){$health['last_http_status']=(int)$match[1];}$health['last_error_at']=time();$health['last_checked']=time();$health['failures']=$count;$health['next_due']=time()+$delay;$health['next_retry']=$health['next_due'];$health['retry_backoff_seconds']=$delay;$health['job']='Failed';$this->store->put('health:'.$source,$health);$this->store->log($source,$error->getMessage());
 }
 public function kev(){
  $previous=$this->store->get('kev_catalog');$health=$this->store->get('health:kev',[]);$response=$this->request('kev',[], $previous?$health:[]);
  if($response['status']===304){cdra_need($previous!==null,'kev_304_without_cache');$this->success('kev',$response,false);return;}
  $data=cdra_kev($response['body']);
  if($previous){cdra_need(cdra_time($data['catalog']['dateReleased'])>=cdra_time($previous['dateReleased']),'kev_catalog_rollback');if($previous['dateReleased']===$data['catalog']['dateReleased']){cdra_need(cdra_hash($previous)===cdra_hash($data['catalog']),'kev_changed_without_version');}}
  $this->store->transaction(function()use($data,$response){$this->store->query("UPDATE {$this->store->prefix}items SET active=0 WHERE source='kev'");foreach($data['rows'] as $record){$this->store->upsert($record);}$this->store->put('kev_catalog',$data['catalog']);$this->success('kev',$response);});
  $this->store->reprioritize();
 }
 public function feeds($source){
  $health=$this->store->get('health:'.$source,[]);$response=$this->request($source,[],$this->store->count($source)?$health:[]);
  if($response['status']===304){cdra_need($this->store->count($source)>0,'feed_304_without_cache');$this->success($source,$response,false);return;}
  $rows=cdra_feed($response['body'],$source);$this->store->transaction(function()use($rows,$source,$response){foreach($rows as $record){$this->store->upsert($record);}$this->success($source,$response);});
 }
 public function page($query){$response=$this->request('nvd',$query);cdra_need($response['status']===200,'nvd_unexpected_304');return [cdra_nvd_page($response['body'],$query),$response];}
 public function nvd($backfill=false){
  $s=$this->store;
  if(!$backfill&&!$s->get('nvd_window')){
   $catalog=$s->get('kev_catalog');cdra_need($catalog!==null,'kev_required');$known=[];
   foreach($s->db->get_results("SELECT source_id,last_seen FROM {$s->prefix}items WHERE source='nvd'",ARRAY_A) as $known_row){$known[$known_row['source_id']]=strtotime($known_row['last_seen'].' UTC');}
   $lookups=$s->get('nvd_kev_lookup',[]);$ids=[];
   foreach($catalog['vulnerabilities'] as $row){$id=$row['cveID'];if((!isset($known[$id])||time()-$known[$id]>604800)&&($lookups[$id]??0)<=time()){$ids[]=$id;if(count($ids)===3){break;}}}
   if($ids){
    [$page,$response]=$this->page(['cveIds'=>implode(',',$ids),'resultsPerPage'=>50,'startIndex'=>0]);
    $s->transaction(function()use($s,$page,$response,$ids,&$lookups,$catalog){foreach($page['rows'] as $record){$s->upsert($record);}foreach($ids as $id){$lookups[$id]=time()+86400;}$allowed=array_fill_keys(array_column($catalog['vulnerabilities'],'cveID'),true);$s->put('nvd_kev_lookup',array_intersect_key($lookups,$allowed));$s->put('nvd_primed',true);$this->success('nvd',$response);});
   }
  }
  cdra_nvd_progress($this,$backfill);
 }

 public function projection(){
  $s=$this->store;$catalog=$s->get('kev_catalog');$nvd=[];$versions=[];
  if($catalog){
   $sql="SELECT DISTINCT n.id,n.payload,n.last_seen,n.source_updated FROM {$s->prefix}items n JOIN {$s->prefix}cves a ON a.item_id=n.id JOIN {$s->prefix}cves b ON b.cve=a.cve JOIN {$s->prefix}items k ON k.id=b.item_id WHERE n.source='nvd' AND k.source='kev' AND k.active=1 ORDER BY n.source_updated DESC,n.id DESC LIMIT 2000";
   foreach($s->db->get_results($sql,ARRAY_A) as $row){$r=json_decode($row['payload'],true,64,JSON_THROW_ON_ERROR);$id=$r['cve_ids'][0];$nvd[$id]=['schema'=>1,'record'=>['id'=>$id,'description'=>$r['summary'],'assessment'=>$r['assessment']],'checked_at'=>strtotime($row['last_seen'].' UTC'),'snapshot'=>false];$v=$r['assessment']['version']??'Not rated';$versions[$v]=($versions[$v]??0)+1;}
  }
  $sources=[];foreach(cdra_sources() as $id=>$spec){$sources[$id]=$s->get('health:'.$id,[]);}
  $projection=['schema'=>2,'generated_at'=>time(),'sources'=>$sources,'kev'=>$catalog?['schema'=>1,'catalog'=>$catalog,'source'=>cdra_sources()['kev']['url'],'fetched_at'=>$sources['kev']['last_received']??0,'snapshot'=>false]:null,'nvd'=>$nvd,'metric_versions'=>$versions,'indexed_cves'=>$s->count('nvd'),'queue_total'=>$s->count(),'nvd_origin'=>$s->get('nvd_origin'),'nvd_checkpoint'=>$s->get('nvd_checkpoint'),'nvd_window'=>cdra_nvd_progress_view($s->get('nvd_window')),'nvd_last_completed_window'=>cdra_nvd_progress_view($s->get('nvd_last_completed_window')),'backfill'=>$s->get('backfill',['status'=>'not_requested']),'nvd_last_incremental_success'=>$s->get('nvd_last_incremental_success',0),'complete_nvd'=>false];
  $json=cdra_json($projection);cdra_need(strlen($json)<=12582912,'dashboard_cache_size');$s->put('dashboard',$projection);
  cdra_build_dashboard_analytics($s);
  if($s->prefix===$s->db->prefix.'cdra_'&&defined('WP_CLI')&&WP_CLI&&is_dir('/var/lib/cyberdat-staging/research')){$file='/var/lib/cyberdat-staging/research/dashboard.json';$temporary=$file.'.partial';cdra_need(!is_link($file)&&!is_link($temporary),'cache_symlink');$written=@file_put_contents($temporary,$json,LOCK_EX);cdra_need($written===strlen($json),'cache_file_write');chmod($temporary,0600);cdra_need(rename($temporary,$file),'cache_file_rename');}
 }
 public function sync($source,$manual=false,$scheduled=false){$this->scheduled=(bool)$scheduled;$this->metric_baseline=$this->store->metrics??[];
  cdra_need(cdra_staging(),'staging_only');$s=$this->store;$db=$s->db;$lock='cdra_'.substr(hash('sha256',DB_NAME.$s->prefix),0,32);
  cdra_need((int)$db->get_var($db->prepare('SELECT GET_LOCK(%s,0)',$lock))===1,'ingestion_locked');$errors=[];
  try{
   $names=$source==='all'?array_keys(cdra_sources()):[$source];
   foreach($names as $name){
    cdra_need(isset(cdra_sources()[$name])||isset(cdra_discovery_registry()[$name]),'source_not_allowed');if(isset(cdra_discovery_registry()[$name])&&!cdra_discovery_enabled($name,$s)){continue;}$health=$s->get('health:'.$name,[]);
    if(($health['next_due']??0)>time()&&(!$manual||!empty($health['last_error']))){continue;}
    if($manual&&time()-($health['last_attempt']??0)<($name==='nvd'?31:300)){continue;}
    $health['job']='Running';$health['last_attempt']=time();$health['last_http_status']=null;if($this->scheduled){$health['last_scheduled_attempt']=time();}$s->put('health:'.$name,$health);
    try{if($name==='kev'){$this->kev();}elseif($name==='nvd'){$this->nvd();}elseif(isset(cdra_discovery_registry()[$name])){cdra_discovery_ingest($this,$name);}else{$this->feeds($name);}$s->log($name,'sync_complete');}
    catch(Throwable $error){$error=$error instanceof CDRA_Error?$error:new CDRA_Error('processing_error');if($error->getMessage()==='academic_pagination_shift'&&isset(cdra_discovery_registry()[$name])){$window=$s->get('discovery_window:'.$name);if($window){$window['offset']=0;$window['seen']=[];$s->put('discovery_window:'.$name,$window);}}$this->fail($name,$error);$errors[$name]=$error->getMessage();}
   }
   $this->projection();
  }finally{$db->get_var($db->prepare('SELECT RELEASE_LOCK(%s)',$lock));}
  return ['errors'=>$errors,'requests'=>$this->requests,'health'=>$s->get('dashboard')['sources'],'kev'=>$s->get('kev_catalog')['count']??0,'nvd'=>$s->count('nvd'),'queue'=>$s->count(),'run_stats'=>array_intersect_key($s->metrics??[],array_flip($names)),'scheduled'=>$this->scheduled,'checkpoint'=>$s->get('nvd_checkpoint'),'coverage_origin'=>$s->get('nvd_origin'),'window'=>cdra_nvd_progress_view($s->get('nvd_window')),'last_completed_window'=>$s->get('nvd_last_completed_window'),'backfill'=>$s->get('backfill',['status'=>'not_requested'])];
 }
 public function backfill($start,$end){cdra_need($end>$start&&$end-$start<=7*86400&&$start>=strtotime('1999-01-01 UTC')&&$end<=time(),'backfill_range');$old=$this->store->get('backfill');cdra_need(!$old||$old['status']!=='active','backfill_already_active');$this->store->transaction(function()use($start,$end){$this->store->put('backfill',['start'=>$start,'end'=>$end,'status'=>'active','next_due'=>time(),'last_success'=>0]);$this->store->put('nvd_backfill_window',null);$this->store->put('nvd_backfill_checkpoint',$start);});}
}
