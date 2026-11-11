<?php
/** Explicit owner acceptance only: three real records, isolated writes, no real queue selections. */
function cdca_evidence_network_test(){
 global $wpdb;$p=$wpdb->prefix.'cdca_test_network_'.bin2hex(random_bytes(4)).'_';$s=new CDCA_Evidence_Store($wpdb,$p);$lock='cdra_'.substr(hash('sha256',DB_NAME.$wpdb->prefix.'cdra_'),0,32);cdca_need((int)$wpdb->get_var($wpdb->prepare('SELECT GET_LOCK(%s,0)',$lock))===1,'ingestion_busy');
 $report=[];
 try{
  usleep(5000000);
  foreach(array_merge(CDCA_Store::schemas($p,$wpdb->get_charset_collate()),CDCA_Evidence_Store::schemas($p,$wpdb->get_charset_collate())) as $schema){$s->query(str_replace('CREATE TABLE ','CREATE TEMPORARY TABLE ',$schema));}
  foreach([['arxiv','paper'],['cisa-advisories','news'],['kev','vulnerability']] as [$source,$template]){
   $rid=(int)$wpdb->get_var($wpdb->prepare("SELECT id FROM {$wpdb->prefix}cdra_items WHERE source=%s ORDER BY id DESC LIMIT 1",$source));$e=cdca_research_evidence($rid,false);$e['topic_id']=hash('sha256','live-fixture-'.$rid);$id=$s->create($e,$template,true,'bounded-network-fixture');$client=new CDCA_Enrichment_Client();$r=cdca_enrich($id,true,$s,$client,$e);$before=$client->requests;try{$again=cdca_enrich($id,true,$s,$client,$e);}catch(CDCA_Error $ex){cdca_need($ex->getMessage()==='enrichment_backoff','repeat_retry_failure');}cdca_need($before===$client->requests,'network_duplicate_fetch');
   $latest=$s->latest($s->read($id));$payload=json_decode($latest['payload'],true);$report[]=['source'=>$source,'research_item'=>$rid,'status'=>$r['status'],'source_results'=>$r['source_results'],'requests'=>$client->requests,'fragments'=>count($payload['evidence']['fragments']??[]),'levels'=>array_column(array_column($payload['evidence']['sources'],'content'),'level'),'repeated_without_fetch'=>true];
  }
  WP_CLI::line('BOUNDED NETWORK EVIDENCE: '.cdca_json($report));WP_CLI::success('Three real inputs; enrichment writes in TEMPORARY fixture tables only.');
 }finally{foreach(['jobs','versions','events','agents','enrichments','evidence'] as $name){$wpdb->query("DROP TEMPORARY TABLE IF EXISTS {$p}{$name}");}$wpdb->get_var($wpdb->prepare('SELECT RELEASE_LOCK(%s)',$lock));}
}
