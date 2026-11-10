<?php
/** CLI-only, isolated MariaDB TEMPORARY tables. Fixtures never enter the real queue. */
defined('ABSPATH') || exit;
class CDRA_Test_Client {
 public $responses;public $queries=[];
 public function __construct($responses){$this->responses=$responses;}
 public function get($source,$query=[],$validators=[]){$this->queries[]=[$source,$query,$validators];cdra_need(count($this->responses)>0,'test_unexpected_request');$next=array_shift($this->responses);if($next instanceof Throwable){throw $next;}return ['status'=>$next['status']??200,'body'=>isset($next['body'])?$next['body']:cdra_json($next),'headers'=>$next['headers']??[]];}
}
function cdra_database_tests(){
 cdra_need(cdra_staging()&&defined('WP_CLI')&&WP_CLI,'test_staging_only');$s=new CDRA_Store();$real=$s->prefix;$s->prefix=$real.'test_'.bin2hex(random_bytes(4)).'_';$tables=['items','aliases','cves','state','logs','events'];$created=[];$original_user=get_current_user_id();
 $check=static function($ok,$label){cdra_need($ok,'self_test_failed');WP_CLI::line('PASS: '.$label);};
 try{
  foreach($tables as $table){$s->query("CREATE TEMPORARY TABLE {$s->prefix}$table LIKE {$real}$table");$created[]=$table;}
  $fixture=json_decode(file_get_contents(__DIR__.'/fixtures.json'),true,64,JSON_THROW_ON_ERROR);$catalog=cdra_kev(cdra_json($fixture['kev']));$record=$catalog['rows'][0];
  $s->transaction(function()use($s,$record,$catalog){$s->upsert($record);$s->put('kev_catalog',$catalog['catalog']);});$s->transaction(static fn()=>$s->upsert($record));$check($s->count()===1,'repeat KEV upsert creates no duplicate');
  $nvd=cdra_nvd_page(cdra_json($fixture['nvd']),['startIndex'=>0])['rows'][0];$id=$s->transaction(static fn()=>$s->upsert($nvd));$s->transaction(static fn()=>$s->upsert($nvd));$check($s->count('nvd')===1&&$s->kev($nvd['cve_ids']),'NVD idempotency and confirmed KEV relationship');
  $advisory=cdra_base('cert-eu','test-guid-1','https://cert.europa.eu/publications/security-advisories/test-1','TEST FIXTURE advisory','TEST fixture never in real queue','2020-01-01T01:00:00Z','2020-01-01T06:00:00Z',['CVE-2020-0001']);
  $a=$s->transaction(static fn()=>$s->upsert($advisory));$alias=$advisory;$alias['source_id']='test-guid-alias';$alias['canonical_url']=cdra_url($alias['canonical_url'].'?utm_source=test');$alias_id=$s->transaction(static fn()=>$s->upsert($alias));$check($a===$alias_id,'canonical URL dedup with source-ID alias');
  $advisory['canonical_url']='https://cert.europa.eu/publications/security-advisories/test-updated';$advisory['source_updated']='2020-01-01T07:00:00Z';$check($s->transaction(static fn()=>$s->upsert($advisory))===$a,'original source ID survives canonical/alias changes');
  $different=$advisory;$different['source_id']='test-guid-2';$different['canonical_url']='https://cert.europa.eu/publications/security-advisories/test-2';$s->transaction(static fn()=>$s->upsert($different));$check($s->count('cert-eu')===2,'different advisories sharing a CVE are not merged');
  $hash=$s->db->get_var($s->db->prepare("SELECT content_hash FROM {$s->prefix}items WHERE id=%d",$id));
  $admin=get_user_by('login','cyberdat_staging_admin');cdra_need($admin,'test_administrator_missing');wp_set_current_user($admin->ID);$nonce=wp_create_nonce('cdra_item_'.$id);$input=['item_id'=>(string)$id,'status'=>'under_review','priority'=>'77','content_hash'=>$hash];
  $check(cdra_editorial_authorized($input,$nonce)[0]===$id,'WordPress capability/nonce adapter authorizes review');
  wp_set_current_user(0);try{cdra_editorial_authorized($input,$nonce);throw new RuntimeException('Unauthorized review');}catch(CDRA_Error $error){$check($error->getMessage()==='editorial_forbidden','anonymous WordPress user cannot review');}wp_set_current_user($original_user);
  foreach(array_keys(cdra_statuses()) as $status){$s->editorial($id,$status,77,1,$hash);$row=$s->db->get_row($s->db->prepare("SELECT editorial_status,manual_priority FROM {$s->prefix}items WHERE id=%d",$id),ARRAY_A);$check($row['editorial_status']===$status&&(int)$row['manual_priority']===77,'editorial status and manual priority '.$status);}
  $nvd['summary'].=' Updated fixture';$nvd['source_updated']='2020-01-01T08:00:00Z';$s->transaction(static fn()=>$s->upsert($nvd));$row=$s->db->get_row($s->db->prepare("SELECT editorial_status,manual_priority,content_hash FROM {$s->prefix}items WHERE id=%d",$id),ARRAY_A);
  $check($row['editorial_status']==='archived'&&(int)$row['manual_priority']===77&&$row['content_hash']!==$hash,'source updates preserve manual review and update evidence hash');
  try{$s->editorial($id,'approved_for_draft',null,1,$hash);throw new RuntimeException('Stale review accepted');}catch(CDRA_Error $e){$check($e->getMessage()==='source_changed_reload','stale browser review cannot approve changed evidence');}
  $s->editorial($id,'approved_for_draft',77,1,$row['content_hash']);$nvd['summary'].=' New unreviewed source update';$nvd['source_updated']='2020-01-01T09:00:00Z';$s->transaction(static fn()=>$s->upsert($nvd));$approval=$s->db->get_row($s->db->prepare("SELECT editorial_status,approved_hash FROM {$s->prefix}items WHERE id=%d",$id),ARRAY_A);$check($approval['editorial_status']==='under_review'&&$approval['approved_hash']===null,'changed evidence invalidates old draft approval');
  $saved=$s->get('kev_catalog');$client=new CDRA_Test_Client([new CDRA_Error('http_503',1800)]);$service=new CDRA_Service($s,$client,static function($seconds){});$result=$service->sync('kev');$check($result['errors']['kev']==='http_503'&&$s->get('kev_catalog')===$saved,'network failure retains last validated KEV catalog');$check($s->get('health:kev')['next_due']>=time()+1799,'Retry-After preserved');
  $s->put('health:kev',['last_received'=>10000,'last_success'=>10000,'last_attempt'=>0,'next_due'=>0]);$service=new CDRA_Service($s,new CDRA_Test_Client([['status'=>304,'body'=>'','headers'=>['etag'=>'"fixture"']]]));$service->sync('kev');$h=$s->get('health:kev');$check($h['last_received']===10000&&$h['last_success']>10000&&$s->get('kev_catalog')===$saved,'304 checks advance verification, not received/source date');
  $s->put('nvd_primed',true);$s->put('nvd_window',['start'=>'2020-01-01T00:00:00Z','end'=>'2020-01-02T00:00:00Z','index'=>0,'total'=>null]);$s->put('health:nvd',[]);
  $first=$fixture['nvd'];$first['totalResults']=2;$waits=[];$pause=static function($seconds)use(&$waits){$waits[]=$seconds;};
  $client=new CDRA_Test_Client([$first,new CDRA_Error('http_429',900)]);$result=(new CDRA_Service($s,$client,$pause))->sync('nvd');$check(($s->get('nvd_window')['index']??0)===1&&$s->get('nvd_checkpoint')===null,'partial pagination persists page cursor without false checkpoint');$check($waits&&min($waits)>=30,'public NVD request pacing enforced');
  $second=$fixture['nvd'];$second['totalResults']=2;$second['startIndex']=1;$second['vulnerabilities'][0]['cve']['id']='CVE-2020-0002';$s->put('health:nvd',[]);
  (new CDRA_Service($s,new CDRA_Test_Client([$second]),$pause))->sync('nvd');$check($s->get('nvd_window')===null&&$s->get('nvd_checkpoint')===strtotime('2020-01-02 UTC')&&$s->count('nvd')===2,'interrupted pagination resumes and completes only the bounded window');
  $service=new CDRA_Service($s);$service->backfill(strtotime('2019-12-01 UTC'),strtotime('2019-12-03 UTC'));$check($s->get('backfill')['status']==='active'&&$s->get('nvd_checkpoint')===strtotime('2020-01-02 UTC'),'bounded backfill keeps a separate live checkpoint');
  try{$s->transaction(function()use($s,$different){$different['source_id']='rollback-test';$different['canonical_url']='https://cert.europa.eu/rollback-test';$s->upsert($different);throw new CDRA_Error('test_rollback');});}catch(CDRA_Error $e){}$check($s->count('cert-eu')===2,'transaction failure cannot partially replace good records');
  $check((int)$s->db->get_var("SELECT COUNT(*) FROM {$s->prefix}events")===8,'editorial audit persisted only in temporary tables');
  WP_CLI::success('Fixed-fixture database integration tests; no network, no real queue data or WordPress posts changed.');
 }finally{wp_set_current_user($original_user);foreach(array_reverse($created) as $table){$s->db->query("DROP TEMPORARY TABLE {$s->prefix}$table");}}
}
