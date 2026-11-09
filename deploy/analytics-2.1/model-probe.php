<?php
/** Staging-only metadata + read-only aggregate probe. Does not call cache-mutating cdta_periods. */
if(wp_get_environment_type()!=='staging'||DB_NAME!=='cyberdat_staging'||rtrim(ABSPATH,'/').'/'!=='/var/www/cyberdat-staging/public/'){throw new RuntimeException('wrong_environment');}
$now=time();$out=['utc'=>gmdate('Y-m-d\TH:i:s\Z',$now),'adapter_function'=>function_exists('cdta_snapshot'),'research_function'=>function_exists('cyberdat_research_dashboard'),'persistent_object_cache'=>wp_using_ext_object_cache()];
$d=function_exists('cyberdat_research_dashboard')?cyberdat_research_dashboard():null;
$out['projection_available']=is_array($d);$out['projection_generated_utc']=$d?gmdate('Y-m-d\TH:i:s\Z',$d['generated_at']):null;
$cache=get_option('_transient_cdta_periods_v1',null);$expiry=(int)get_option('_transient_timeout_cdta_periods_v1',0);
$out['cache']=['present'=>is_array($cache),'expires_utc'=>$expiry?gmdate('Y-m-d\TH:i:s\Z',$expiry):null,'expired'=>$expiry>0&&$expiry<=$now,'generated_utc'=>isset($cache['data']['generated_at'])?gmdate('Y-m-d\TH:i:s\Z',$cache['data']['generated_at']):null];
if($d){$signature=hash('sha256',wp_json_encode([$d['generated_at'],$d['counts'],$d['chart_series'],$d['versions']]));$out['cache']['matches_projection']=is_array($cache)&&($cache['signature']??'')===$signature;}
global $wpdb;$p=$wpdb->prefix.'cdra_';$lock='cdra_'.substr(hash('sha256',DB_NAME.$p),0,32);$out['ingestion_lock_free']=(int)$wpdb->get_var($wpdb->prepare('SELECT IS_FREE_LOCK(%s)',$lock))===1;
$out['sources']=[];if(class_exists('CDRA_Store')){$store=new CDRA_Store();foreach(['kev','nvd','cisa-advisories','cert-eu','msrc'] as $id){$h=$store->get('health:'.$id,[]);$out['sources'][$id]=['job'=>$h['job']??null,'last_error'=>$h['last_error']??null,'last_attempt_utc'=>empty($h['last_attempt'])?null:gmdate('Y-m-d\TH:i:s\Z',$h['last_attempt']),'last_success_utc'=>empty($h['last_success'])?null:gmdate('Y-m-d\TH:i:s\Z',$h['last_success'])];}}
if(function_exists('cdta_snapshot')){
 try{$out['snapshot_probe']=cdta_snapshot(static function($db,$p,$snapshot,$revision){
  [$oldest,$end,$cutoff]=cdta_bounds($snapshot,90);$day="CASE WHEN i.source='kev' THEN ".cdta_date('kev')." ELSE DATE(i.published) END";$score=cdta_score();
  $sql=$db->prepare("SELECT i.source,$day AS day,COUNT(*) AS n,SUM(CASE WHEN $score BETWEEN 9 AND 10 THEN 1 ELSE 0 END) AS critical,SUM(CASE WHEN JSON_UNQUOTE(JSON_EXTRACT(i.payload,'$.cisa_original.knownRansomwareCampaignUse'))='Known' THEN 1 ELSE 0 END) AS ransomware FROM {$p}items i WHERE i.active=1 AND i.source IN ('kev','nvd') AND $day BETWEEN %s AND %s AND (i.source='kev' OR i.published<=%s) GROUP BY i.source,day",$oldest,$end,$cutoff);
  $rows=$db->get_results($sql,ARRAY_A);if($db->last_error||!is_array($rows)){throw new RuntimeException('aggregate_query_failed');}
  return ['status'=>'ok','daily_buckets'=>count($rows),'generated_at'=>$snapshot['generated_at'],'generated_utc'=>gmdate('Y-m-d\TH:i:s\Z',$snapshot['generated_at'])];
 });$out['generation_changed_during_probe']=$d&&$out['snapshot_probe']['generated_at']!==$d['generated_at'];}
 catch(Throwable $e){$reason=in_array($e->getMessage(),['updating','database','unavailable','revision','aggregate_query_failed'],true)?$e->getMessage():'other';$out['snapshot_probe']=['status'=>'blocked','reason'=>$reason,'type'=>get_class($e)];}
}
echo wp_json_encode($out);
