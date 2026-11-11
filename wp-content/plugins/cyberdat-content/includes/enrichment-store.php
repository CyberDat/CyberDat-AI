<?php
defined('ABSPATH') || exit;
class CDCA_Evidence_Store extends CDCA_Store {
 public static function schemas($p,$charset){return [
 "CREATE TABLE {$p}enrichments (id bigint unsigned NOT NULL AUTO_INCREMENT, job_id bigint unsigned NOT NULL, research_item bigint unsigned NOT NULL, source_hash char(64) NOT NULL, request_key char(64) NOT NULL, status varchar(24) NOT NULL, attempts int NOT NULL DEFAULT 0, next_attempt bigint NOT NULL DEFAULT 0, last_error varchar(64) NOT NULL DEFAULT '', payload longtext NOT NULL, created bigint NOT NULL, updated bigint NOT NULL, PRIMARY KEY  (id), UNIQUE KEY request_key (request_key), KEY job_created (job_id,id)) ENGINE=InnoDB $charset;",
 "CREATE TABLE {$p}evidence (id bigint unsigned NOT NULL AUTO_INCREMENT, evidence_key char(64) NOT NULL, enrichment_id bigint unsigned NOT NULL, research_item bigint unsigned NOT NULL, source_version_hash char(64) NOT NULL, document longtext NOT NULL, created bigint NOT NULL, PRIMARY KEY  (id), UNIQUE KEY evidence_key (evidence_key), KEY enrichment (enrichment_id)) ENGINE=InnoDB $charset;"
 ];}
 public static function install(){cdca_need(cdca_stage(),'staging_only');global $wpdb;require_once ABSPATH.'wp-admin/includes/upgrade.php';$s=new self();foreach(self::schemas($s->p,$wpdb->get_charset_collate()) as $sql){dbDelta($sql);}foreach(['enrichments','evidence'] as $t){cdca_need($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s',$wpdb->esc_like($s->p.$t)))===$s->p.$t,'evidence_schema');}}
 public function latest($job){$r=$this->db->get_row($this->db->prepare("SELECT * FROM {$this->p}enrichments WHERE job_id=%d AND source_hash=%s ORDER BY id DESC LIMIT 1",(int)$job['id'],$job['source_hash']),ARRAY_A);cdca_need(!$this->db->last_error,'evidence_read');return $r;}
 public function save($job,$payload,$status,$actor,$network=false){
  cdca_need(in_array($status,['complete','partial','blocked','retry_pending'],true),'enrichment_status');cdca_need(strlen(cdca_json($payload))<=240000,'enrichment_size');
  $key=cdca_hash(['evidence/1',(int)$job['id'],$job['source_hash'],(bool)$network]);
  return $this->tx(function()use($job,$payload,$status,$actor,$key){
   $current=$this->read((int)$job['id'],true);cdca_need($current['revision']===$job['revision']&&$current['status']===$job['status'],'enrichment_job_changed');
   $old=$this->db->get_row($this->db->prepare("SELECT * FROM {$this->p}enrichments WHERE request_key=%s FOR UPDATE",$key),ARRAY_A);
   if($old&&in_array($old['status'],['complete','partial','blocked'],true)){return (int)$old['id'];}
   $attempts=1+(int)($old['attempts']??0);cdca_need($attempts<=3,'enrichment_retry_exhausted');
   $data=['job_id'=>(int)$job['id'],'research_item'=>(int)$job['research_item'],'source_hash'=>$job['source_hash'],'request_key'=>$key,'status'=>$status,'attempts'=>$attempts,'next_attempt'=>$status==='retry_pending'?$this->now()+max(min(3600,300*2**($attempts-1)),min(86400,(int)($payload['retry_after']??0))):0,'last_error'=>$payload['last_error']??'','payload'=>cdca_json($payload),'updated'=>$this->now()];
   if($old){cdca_need((int)$old['next_attempt']<=$this->now(),'enrichment_backoff');cdca_need($this->db->update($this->p.'enrichments',$data,['id'=>$old['id']])!==false,'enrichment_write');$id=(int)$old['id'];}
   else{$data['created']=$this->now();cdca_need($this->db->insert($this->p.'enrichments',$data)!==false,'enrichment_write');$id=(int)$this->db->insert_id;}
   foreach($payload['evidence']['fragments']??[] as $fragment){$ek=cdca_hash([$id,$fragment['id']]);$document=cdca_json($fragment);cdca_need(strlen($document)<=18000,'fragment_size');
    $this->query($this->db->prepare("INSERT IGNORE INTO {$this->p}evidence (evidence_key,enrichment_id,research_item,source_version_hash,document,created) VALUES (%s,%d,%d,%s,%s,%d)",$ek,$id,$fragment['research_item_id'],$fragment['source_version_hash'],$document,$this->now()));}
   $this->event((int)$job['id'],'evidence_'.$status,$job['status'],$job['status'],$actor);return $id;
  });
 }
}
function cdca_enrichment_request($job_id,$revision,$actor){
 $s=new CDCA_Evidence_Store();return $s->tx(function()use($s,$job_id,$revision,$actor){$job=$s->read($job_id,true);cdca_need((int)$job['revision']===$revision,'stale_review');cdca_need(in_array($job['status'],['selected','queued'],true),'enrichment_editorial_lock');cdca_need(cdca_research_current($job),'research_changed');$key=cdca_hash(['evidence/1',$job_id,$job['source_hash'],true]);
  $old=$s->db->get_var($s->db->prepare("SELECT id FROM {$s->p}enrichments WHERE request_key=%s",$key));if($old){return (int)$old;}
  cdca_need($s->db->insert($s->p.'enrichments',['job_id'=>$job_id,'research_item'=>$job['research_item'],'source_hash'=>$job['source_hash'],'request_key'=>$key,'status'=>'pending','payload'=>'{}','created'=>$s->now(),'updated'=>$s->now()])!==false,'enrichment_write');$id=(int)$s->db->insert_id;$s->event($job_id,'enrichment_requested',$job['status'],$job['status'],$actor);return $id;});
}
function cdca_enrich($job_id,$network=false,$store=null,$client=null,$evidence=null){
 cdca_need(cdca_stage()&&defined('WP_CLI')&&WP_CLI,'enrichment_cli_only');$s=$store??new CDCA_Evidence_Store();$lock='cdca_evidence_'.substr(hash('sha256',$s->p),0,32);
 cdca_need((int)$s->db->get_var($s->db->prepare('SELECT GET_LOCK(%s,0)',$lock))===1,'enrichment_busy');
 try{
  $job=$s->read($job_id);cdca_need(in_array($job['status'],['selected','queued'],true),'enrichment_editorial_lock');
  if($evidence===null){cdca_need(cdca_research_current($job),'research_changed');}else{cdca_need($evidence['source_hash']===$job['source_hash'],'research_changed');}
  $key=cdca_hash(['evidence/1',$job_id,$job['source_hash'],(bool)$network]);$old=$s->db->get_row($s->db->prepare("SELECT * FROM {$s->p}enrichments WHERE request_key=%s",$key),ARRAY_A);
  if($old&&in_array($old['status'],['complete','partial','blocked'],true)){return ['id'=>(int)$old['id'],'idempotent'=>true,'status'=>$old['status']];}
  cdca_need(!$old||(int)$old['attempts']<3,'enrichment_retry_exhausted');cdca_need(!$old||(int)$old['next_attempt']<=$s->now(),'enrichment_backoff');
  // Supplying evidence/client is restricted to explicitly TEST jobs in isolated fixture tables.
  if($evidence!==null||$client!==null){cdca_need((int)$job['is_test']===1&&str_contains($s->p,'test_'),'fixture_scope');}
  $ingestion_lock=null;if($network&&$client===null){$ingestion_lock='cdra_'.substr(hash('sha256',DB_NAME.$s->db->prefix.'cdra_'),0,32);cdca_need((int)$s->db->get_var($s->db->prepare('SELECT GET_LOCK(%s,0)',$ingestion_lock))===1,'ingestion_busy');usleep(5000000);}
  $e=$evidence??cdca_selected_evidence((int)$job['research_item']);cdca_need($e['source_hash']===$job['source_hash'],'research_changed');$client=$client??new CDCA_Enrichment_Client();$results=[];$retry=0;$error='';$network_calls=0;
  if($network){foreach($e['sources'] as &$source){
   if($network_calls>=2){$results[]=['source_id'=>$source['id'],'status'=>'bounded_deferred'];continue;}
   $url=null;if(($source['source']??'')==='arxiv'&&!empty($source['paper']['arxiv_id'])){$url='https://export.arxiv.org/api/query?id_list='.rawurlencode($source['paper']['arxiv_id']);}
   elseif(($source['source']??'')==='cisa-advisories'){$url=$source['url'];}
   elseif(($source['source']??'')==='kev'){$url='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';}
   if(!$url){$results[]=['source_id'=>$source['id'],'status'=>'access_not_permitted','reason'=>'No extraction/usage policy for this source; existing metadata retained.'];continue;}
   ++$network_calls;$result_index=null;
   try{$response=$client->fetch($url);$result_index=count($results);$results[]=['source_id'=>$source['id'],'status'=>$response['status'],'http_status'=>$response['http_status']??null,'curl_errno'=>$response['curl_errno']??null];
    if($response['status']==='ok'){$content=$client->extract($response,$source);$source['content']=$content;unset($source['content']['text'],$source['content']['locator'],$source['content']['evidence_type']);$f=['id'=>'E'.substr(cdca_hash([$source['research_item_id'],$source['content_hash'],$content['content_hash']]),0,32),'research_item_id'=>$source['research_item_id'],'source_id'=>$source['id'],'source'=>$source['source'],'url'=>$content['content_source_url'],'source_type'=>'official_metadata','published'=>$source['published'],'received_at'=>$content['content_fetched_at'],'text'=>$content['text'],'locator'=>$content['locator'],'context'=>$source['title'],'evidence_type'=>$content['evidence_type'],'verification_status'=>'unverified','source_version_hash'=>$source['content_hash'],'retrieved_content_hash'=>$content['content_hash'],'limitations'=>$content['limitations']];$e['fragments'][]=$f;}
    elseif(($response['retry_after']??0)>0){$retry=max($retry,$response['retry_after']);$error=$response['status'];}
   }catch(CDCA_Error $ex){$code=$ex->getMessage();if($result_index!==null){$results[$result_index]['status']=$code;}else{$results[]=['source_id'=>$source['id'],'status'=>$code];}$error=$code;if($code==='enrichment_dns'){$retry=max($retry,300);}}
  }unset($source);}
  else{$results[]=['status'=>'local_database_only','reason'=>'Existing Research metadata and related official CVE records; no HTTP requests.'];}
  $e['sufficiency']=cdca_sufficiency($e,$job['template']);$payload=['schema'=>'cyberdat-enrichment/1','evidence'=>$e,'sources'=>$results,'network_requested'=>(bool)$network,'retry_after'=>$retry,'last_error'=>$error];
  $status=$retry>0?'retry_pending':($network&&count(array_filter($results,static fn($r)=>($r['status']??'')!=='ok'))?'partial':'complete');
  // Source updates during a network request must not silently attach to a newer snapshot.
  if($evidence===null){cdca_need(cdca_research_current($job),'research_changed');}
  $id=$s->save($job,$payload,$status,'enrichment-cli',$network);return ['id'=>$id,'status'=>$status,'gate'=>$e['sufficiency'],'source_results'=>$results];
 }finally{if(!empty($ingestion_lock)){$s->db->get_var($s->db->prepare('SELECT RELEASE_LOCK(%s)',$ingestion_lock));}$s->db->get_var($s->db->prepare('SELECT RELEASE_LOCK(%s)',$lock));}
}
function cdca_job_brief($job,$store=null){
 $brief=json_decode($job['brief'],true,64,JSON_THROW_ON_ERROR);$s=$store??new CDCA_Evidence_Store();$row=$s->latest($job);
 if($row&&in_array($row['status'],['complete','partial'],true)){$p=json_decode($row['payload'],true,64,JSON_THROW_ON_ERROR);if(isset($p['evidence'])){$brief=cdca_brief($p['evidence'],$job['template'],(bool)$job['is_test']);$brief['enrichment_snapshot']=['id'=>(int)$row['id'],'updated'=>(int)$row['updated'],'hash'=>hash('sha256',$row['payload'])];}}
 return $brief;
}
