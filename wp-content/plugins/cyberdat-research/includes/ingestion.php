<?php
defined('ABSPATH') || exit;
class CDRA_Service {
 public $store;public $client;public $started;public $requests=0;public $pause;
 public function __construct($store=null,$client=null,$pause=null){$this->pause=$pause??'sleep';$this->store=$store??new CDRA_Store();$this->client=$client??new CDRA_Client();$this->started=microtime(true);}
 public static function nvd_pending_due($store,$now=null){$h=$store->get('health:nvd',[]);return (bool)$store->get('nvd_window')&&($h['next_due']??0)<=($now??time())&&($h['failures']??0)<6;}
 public function request($source,$query=[],$conditional=[]){
  cdra_need(microtime(true)-$this->started<110&&$this->requests<6,'run_budget');
  if($source==='nvd'){$wait=max(0,$this->store->get('nvd_request_after',0)-time());cdra_need($wait<=35&&microtime(true)-$this->started+$wait<110,'rate_budget');if($wait){call_user_func($this->pause,$wait);}$this->store->put('nvd_request_after',time()+31);}
  $health=$this->store->get('health:'.$source,[]);$health['job']='Running';$health['last_attempt']=time();$this->store->put('health:'.$source,$health);++$this->requests;return $this->client->get($source,$query,$conditional);
 }
 public function success($source,$response,$received=true){
  $health=$this->store->get('health:'.$source,[]);$health['last_success']=time();$health['last_checked']=time();if($received){$health['last_received']=time();}
  $health['last_error']='';$health['failures']=0;$health['job']='Idle';$health['last_http_status']=$response['status'];if(cdra_sources()[$source]['format']==='rss'){$health['coverage']=!empty($response['bounded_feed_prefix'])?'first_'.(int)($response['bounded_feed_records']??25).'_complete_XML_records':'bounded_feed_document';}$health['next_due']=time()+cdra_sources()[$source]['interval'];
  if($source!=='nvd'){foreach(['etag'=>'etag','last-modified'=>'last_modified'] as $key=>$field){if(isset($response['headers'][$key])&&strlen($response['headers'][$key])<=512&&!preg_match('/[\r\n\x00]/',$response['headers'][$key])){$health[$field]=$response['headers'][$key];}}}
  $this->store->put('health:'.$source,$health);
 }
 public function fail($source,$error){
  $health=$this->store->get('health:'.$source,[]);$count=min(9,($health['failures']??0)+1);$delay=max($error->retry,min(86400,300*2**($count-1)),in_array($error->getMessage(),['http_403','http_429'],true)?900:0);
  $health['last_error']=$error->getMessage();if(preg_match('/^http_(\d{3})$/D',$error->getMessage(),$match)){$health['last_http_status']=(int)$match[1];}$health['last_error_at']=time();$health['last_checked']=time();$health['failures']=$count;$health['next_due']=time()+$delay;$health['job']='Failed';$this->store->put('health:'.$source,$health);$this->store->log($source,$error->getMessage());
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
  $key=$backfill?'nvd_backfill_window':'nvd_window';$checkpoint_key=$backfill?'nvd_backfill_checkpoint':'nvd_checkpoint';
  $max=$this->requests===0?2:1;
  for($i=0;$i<$max;++$i){
   $window=$s->get($key);
   if(!$window){
    if($backfill){$request=$s->get('backfill');cdra_need($request&&$request['status']==='active','no_backfill_requested');$start=$s->get($checkpoint_key,$request['start']);if($start>=$request['end']){$request['status']='complete';$s->put('backfill',$request);return;}$end=min($request['end'],$start+86400);}
    else{$end=time()-600;$checkpoint=$s->get($checkpoint_key);$start=$checkpoint?$checkpoint-7200:$end-86400;$end=min($end,$start+86400);}
    $window=['start'=>gmdate('Y-m-d\TH:i:s\Z',$start),'end'=>gmdate('Y-m-d\TH:i:s\Z',$end),'index'=>0,'total'=>null,'pages'=>[]];$s->put($key,$window);
   }
   // Older windows may lack a page ledger. Audit only their committed prefix;
   // keep the cursor and resume after it instead of blindly reimporting the window.
   $pages=$window['pages']??[];$verified=0;
   foreach($pages as $entry){cdra_need($entry['index']===$verified,'nvd_ledger_gap');$verified+=count($entry['ids']);}
   cdra_need($verified<=$window['index'],'nvd_ledger_ahead');
   $offset=$verified<$window['index']?$verified:$window['index'];
   [$page,$response]=$this->page(['lastModStartDate'=>$window['start'],'lastModEndDate'=>$window['end'],'resultsPerPage'=>50,'startIndex'=>$offset]);
   cdra_need($page['total']<=5000,'nvd_window_capacity');
   if($window['total']!==null&&$window['total']!==$page['total']){
    // NVD has no snapshot token. A changing result set cannot safely keep offsets.
    $window['index']=0;$window['total']=null;$window['pages']=[];$s->put($key,$window);throw new CDRA_Error('nvd_pagination_changed');
   }
   $ids=array_column($page['rows'],'source_id');$seen=[];
   foreach($pages as $entry){foreach($entry['ids'] as $id){$seen[$id]=true;}}
   if(array_intersect(array_keys($seen),$ids)){$window['index']=0;$window['total']=null;$window['pages']=[];$s->put($key,$window);throw new CDRA_Error('nvd_pagination_overlap');}
   $done=false;
   $s->transaction(function()use($s,$page,$response,$ids,$offset,$pages,&$window,&$done,$key,$checkpoint_key,$backfill){
    foreach($page['rows'] as $record){$s->upsert($record);}
    $pages[]=['index'=>$offset,'ids'=>$ids,'hash'=>hash('sha256',implode("\n",$ids))];
    $window['pages']=$pages;$window['total']=$page['total'];$window['index']=max($window['index'],$offset+$page['count']);
    $verified=0;foreach($pages as $entry){cdra_need($entry['index']===$verified,'nvd_ledger_gap');$verified+=count($entry['ids']);}
    $done=$verified===$window['total'];
    if($done){
     $window['completed_at']=time();$window['verified_results']=$verified;$window['status']='Complete';
     $s->put($checkpoint_key,cdra_time($window['end']));$s->put($key,null);
     $s->put($backfill?'nvd_last_completed_backfill':'nvd_last_completed_window',$window);
    }else{$s->put($key,$window);}
    if(!$backfill){
     $s->put('nvd_origin',$s->get('nvd_origin',$window['start']));$this->success('nvd',$response);$s->put('nvd_last_incremental_success',time());
     if(!$done){$h=$s->get('health:nvd');$h['next_due']=time()+300;$s->put('health:nvd',$h);}
    }
    else{$request=$s->get('backfill');$request['last_success']=time();$request['next_due']=time()+7200;if($done&&cdra_time($window['end'])>=$request['end']){$request['status']='complete';}$s->put('backfill',$request);}
   });
   if($done){break;}
  }
 }
 public function projection(){
  $s=$this->store;$catalog=$s->get('kev_catalog');$nvd=[];$versions=[];
  if($catalog){
   $sql="SELECT DISTINCT n.id,n.payload,n.last_seen,n.source_updated FROM {$s->prefix}items n JOIN {$s->prefix}cves a ON a.item_id=n.id JOIN {$s->prefix}cves b ON b.cve=a.cve JOIN {$s->prefix}items k ON k.id=b.item_id WHERE n.source='nvd' AND k.source='kev' AND k.active=1 ORDER BY n.source_updated DESC,n.id DESC LIMIT 2000";
   foreach($s->db->get_results($sql,ARRAY_A) as $row){$r=json_decode($row['payload'],true,64,JSON_THROW_ON_ERROR);$id=$r['cve_ids'][0];$nvd[$id]=['schema'=>1,'record'=>['id'=>$id,'description'=>$r['summary'],'assessment'=>$r['assessment']],'checked_at'=>strtotime($row['last_seen'].' UTC'),'snapshot'=>false];$v=$r['assessment']['version']??'Not rated';$versions[$v]=($versions[$v]??0)+1;}
  }
  $sources=[];foreach(cdra_sources() as $id=>$spec){$sources[$id]=$s->get('health:'.$id,[]);}
  $projection=['schema'=>2,'generated_at'=>time(),'sources'=>$sources,'kev'=>$catalog?['schema'=>1,'catalog'=>$catalog,'source'=>cdra_sources()['kev']['url'],'fetched_at'=>$sources['kev']['last_received']??0,'snapshot'=>false]:null,'nvd'=>$nvd,'metric_versions'=>$versions,'indexed_cves'=>$s->count('nvd'),'queue_total'=>$s->count(),'nvd_origin'=>$s->get('nvd_origin'),'nvd_checkpoint'=>$s->get('nvd_checkpoint'),'nvd_window'=>$s->get('nvd_window'),'nvd_last_completed_window'=>$s->get('nvd_last_completed_window'),'backfill'=>$s->get('backfill',['status'=>'not_requested']),'nvd_last_incremental_success'=>$s->get('nvd_last_incremental_success',0),'complete_nvd'=>false];
  $json=cdra_json($projection);cdra_need(strlen($json)<=12582912,'dashboard_cache_size');$s->put('dashboard',$projection);
  cdra_build_dashboard_analytics($s);
  if($s->prefix===$s->db->prefix.'cdra_'&&defined('WP_CLI')&&WP_CLI&&is_dir('/var/lib/cyberdat-staging/research')){$file='/var/lib/cyberdat-staging/research/dashboard.json';$temporary=$file.'.partial';cdra_need(!is_link($file)&&!is_link($temporary),'cache_symlink');$written=@file_put_contents($temporary,$json,LOCK_EX);cdra_need($written===strlen($json),'cache_file_write');chmod($temporary,0600);cdra_need(rename($temporary,$file),'cache_file_rename');}
 }
 public function sync($source,$manual=false){
  cdra_need(cdra_staging(),'staging_only');$s=$this->store;$db=$s->db;$lock='cdra_'.substr(hash('sha256',DB_NAME.$s->prefix),0,32);
  cdra_need((int)$db->get_var($db->prepare('SELECT GET_LOCK(%s,0)',$lock))===1,'ingestion_locked');$errors=[];
  try{
   $names=$source==='all'?array_keys(cdra_sources()):[$source];
   foreach($names as $name){
    cdra_need(isset(cdra_sources()[$name]),'source_not_allowed');$health=$s->get('health:'.$name,[]);
    if(($health['next_due']??0)>time()&&(!$manual||!empty($health['last_error']))){continue;}
    if($manual&&time()-($health['last_attempt']??0)<($name==='nvd'?31:300)){continue;}
    $health['job']='Running';$health['last_attempt']=time();$s->put('health:'.$name,$health);
    try{if($name==='kev'){$this->kev();}elseif($name==='nvd'){$this->nvd();}else{$this->feeds($name);}$s->log($name,'sync_complete');}
    catch(Throwable $error){$error=$error instanceof CDRA_Error?$error:new CDRA_Error('processing_error');$this->fail($name,$error);$errors[$name]=$error->getMessage();}
   }
   $this->projection();
  }finally{$db->get_var($db->prepare('SELECT RELEASE_LOCK(%s)',$lock));}
  return ['errors'=>$errors,'requests'=>$this->requests,'health'=>$s->get('dashboard')['sources'],'kev'=>$s->get('kev_catalog')['count']??0,'nvd'=>$s->count('nvd'),'queue'=>$s->count(),'checkpoint'=>$s->get('nvd_checkpoint'),'coverage_origin'=>$s->get('nvd_origin'),'window'=>$s->get('nvd_window'),'last_completed_window'=>$s->get('nvd_last_completed_window'),'backfill'=>$s->get('backfill',['status'=>'not_requested'])];
 }
 public function backfill($start,$end){cdra_need($end>$start&&$end-$start<=7*86400&&$start>=strtotime('1999-01-01 UTC')&&$end<=time(),'backfill_range');$old=$this->store->get('backfill');cdra_need(!$old||$old['status']!=='active','backfill_already_active');$this->store->transaction(function()use($start,$end){$this->store->put('backfill',['start'=>$start,'end'=>$end,'status'=>'active','next_due'=>time(),'last_success'=>0]);$this->store->put('nvd_backfill_window',null);$this->store->put('nvd_backfill_checkpoint',$start);});}
}
