<?php
/** Read-only current checkpoint, ledger, dedup and Dashboard/SQL proof. */
cdra_need(cdra_staging(),'staging_only');$s=new CDRA_Store();$s->query('SET TRANSACTION READ ONLY');$s->query('START TRANSACTION WITH CONSISTENT SNAPSHOT');
try{
 $done=$s->get('nvd_last_completed_window');$ids=[];$position=0;
 if($done){foreach($done['pages'] as $page){cdra_need($page['index']===$position&&hash('sha256',implode("\n",$page['ids']))===$page['hash'],'ledger_integrity');foreach($page['ids'] as $id){cdra_need(!isset($ids[$id]),'ledger_duplicate');$ids[$id]=true;}$position+=count($page['ids']);}cdra_need($position===$done['total']&&$position===$done['verified_results'],'ledger_incomplete');}
 $rows=$s->db->get_results("SELECT source_id,payload FROM {$s->prefix}items WHERE source='nvd'",ARRAY_A);$stored=[];$metrics=[];
 foreach($rows as $row){cdra_need(!isset($stored[$row['source_id']]),'duplicate_nvd_id');$stored[$row['source_id']]=true;$metrics[$row['source_id']]=json_decode($row['payload'],true,64,JSON_THROW_ON_ERROR)['assessment'];}
 cdra_need(!array_diff_key($ids,$stored),'completed_cve_missing_from_database');
 $d=$s->get('dashboard');cdra_need($d['indexed_cves']===count($stored),'dashboard_total_mismatch');
 foreach($d['nvd'] as $id=>$entry){cdra_need(array_key_exists($id,$metrics)&&$metrics[$id]===$entry['record']['assessment'],'dashboard_metric_mismatch');}
 $h=$s->get('health:nvd',[]);$window=$s->get('nvd_window');
 $out=['indexed_cves'=>count($stored),'kev_count'=>$d['kev']['catalog']['count'],'kev_matched_chart'=>count($d['nvd']),'checkpoint'=>$s->get('nvd_checkpoint'),'checkpoint_utc'=>$s->get('nvd_checkpoint')?gmdate('Y-m-d\TH:i:s\Z',$s->get('nvd_checkpoint')):null,'window'=>$window?array_diff_key($window,['pages'=>true]):null,'last_completed'=>$done?array_diff_key($done,['pages'=>true]):null,'verified_unique_window_cves'=>count($ids),'missing_completed_ids'=>0,'duplicate_nvd_ids'=>0,'dashboard_sql_match'=>true,'last_success_utc'=>empty($h['last_success'])?null:gmdate('Y-m-d\TH:i:s\Z',$h['last_success']),'last_error'=>$h['last_error']??'','next_due'=>$h['next_due']??0,'historical_nvd_complete'=>false];
 $s->query('COMMIT');echo wp_json_encode($out);
}catch(Throwable $e){$s->db->query('ROLLBACK');throw $e;}
