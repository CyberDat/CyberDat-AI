<?php
/** Independent SQL acceptance checks, not a call to the aggregation function under test. */
cdra_need(cdra_staging(),'staging_only');$s=new CDRA_Store();$s->query('SET TRANSACTION READ ONLY');$s->query('START TRANSACTION WITH CONSISTENT SNAPSHOT');
try{
 $d=$s->get('dashboard_v1');cdra_need(($d['schema']??0)===1,'analytics_missing');$p=$s->prefix;
 $score="CAST(JSON_UNQUOTE(JSON_EXTRACT(payload,'$.assessment.score')) AS DECIMAL(5,2))";
 $expected=['kev'=>(int)$s->db->get_var("SELECT COUNT(*) FROM {$p}items WHERE source='kev' AND active=1"),'nvd'=>(int)$s->db->get_var("SELECT COUNT(*) FROM {$p}items WHERE source='nvd' AND active=1"),'critical'=>(int)$s->db->get_var("SELECT COUNT(*) FROM {$p}items WHERE source='nvd' AND active=1 AND JSON_TYPE(JSON_EXTRACT(payload,'$.assessment.score')) IN ('INTEGER','DOUBLE') AND $score BETWEEN 9 AND 10"),'high'=>(int)$s->db->get_var("SELECT COUNT(*) FROM {$p}items WHERE source='nvd' AND active=1 AND JSON_TYPE(JSON_EXTRACT(payload,'$.assessment.score')) IN ('INTEGER','DOUBLE') AND $score>=7 AND $score<9"),'ransomware'=>(int)$s->db->get_var("SELECT COUNT(*) FROM {$p}items WHERE source='kev' AND active=1 AND JSON_UNQUOTE(JSON_EXTRACT(payload,'$.cisa_original.knownRansomwareCampaignUse'))='Known'"),'advisories'=>(int)$s->db->get_var("SELECT COUNT(*) FROM {$p}items WHERE source IN ('cisa-advisories','cert-eu','msrc') AND active=1")];
 foreach($expected as $key=>$value){cdra_need($d['counts'][$key]===$value,'kpi_sql_mismatch');}
 $day=strtotime($d['reference_day'].' UTC');
 foreach(['nvd_7'=>6,'nvd_30'=>29] as $key=>$days){$value=(int)$s->db->get_var($s->db->prepare("SELECT COUNT(*) FROM {$p}items WHERE source='nvd' AND active=1 AND published>=%s AND published<=%s",gmdate('Y-m-d H:i:s',$day-$days*86400),gmdate('Y-m-d H:i:s',$d['generated_at'])));cdra_need($d['counts'][$key]===$value,'publication_count_sql_mismatch');}
 $histogram=array_fill_keys(['Critical','High','Medium','Low','None','Unrated'],0);
 $metrics=$s->db->get_results("SELECT JSON_EXTRACT(payload,'$.assessment') AS metric FROM {$p}items WHERE source='nvd' AND active=1",ARRAY_A);
 foreach($metrics as $metric){$a=json_decode($metric['metric']??'null',true);$v=$a['score']??null;$label=$v===null?'Unrated':($v>=9?'Critical':($v>=7?'High':($v>=4?'Medium':($v>0?'Low':'None'))));$histogram[$label]++;}
 cdra_need($histogram===$d['severity']&&array_sum($histogram)===$expected['nvd'],'severity_sql_mismatch');
 foreach($d['feed'] as $row){$raw=$s->db->get_row($s->db->prepare("SELECT payload,published,canonical_url FROM {$p}items WHERE source=%s AND source_id=%s LIMIT 1",$row['source'],$row['id']),ARRAY_A);cdra_need($raw&&$raw['published']===$row['published']&&$raw['canonical_url']===$row['url'],'feed_sql_mismatch');$record=json_decode($raw['payload'],true);cdra_need($row['title']===$record['original_title']&&$row['assessment']===$record['assessment'],'feed_evidence_mismatch');}
 $health=[];foreach(cdra_sources() as $id=>$spec){$h=$s->get('health:'.$id,[]);$health[$id]=['last_success_utc'=>empty($h['last_success'])?null:gmdate('Y-m-d\TH:i:s\Z',$h['last_success']),'last_error'=>$h['last_error']??'','coverage'=>$h['coverage']??null];}
 // Independent 90-day SQL aggregation proves every chart point, not only totals.
 $day=strtotime($d['reference_day'].' UTC');$chart_totals=[];
 foreach(['kev','nvd'] as $source){
  $field=$source==='kev'?"JSON_UNQUOTE(JSON_EXTRACT(payload,'$.cisa_original.dateAdded'))":"DATE(published)";
  $sql=$s->db->prepare("SELECT $field AS day,COUNT(*) AS n FROM {$p}items WHERE source=%s AND active=1 AND $field>=%s AND $field<=%s".($source==='nvd'?" AND published<=".$s->db->prepare('%s',gmdate('Y-m-d H:i:s',$d['generated_at'])):'')." GROUP BY day",$source,gmdate('Y-m-d',$day-89*86400),$d['reference_day']);
  $sql_counts=[];foreach($s->db->get_results($sql,ARRAY_A) as $row){$sql_counts[$row['day']]=(int)$row['n'];}
  cdra_need(count($d['chart_series'][$source])===90,'chart_window_size');
  foreach($d['chart_series'][$source] as $date=>$number){cdra_need($number===($sql_counts[$date]??0),'chart_point_sql_mismatch');}
  foreach([7,30,90] as $period){$chart_totals[$source][$period]=array_sum(array_slice($d['chart_series'][$source],-$period,null,true));}
 }
 $overlap=(int)$s->db->get_var("SELECT COUNT(DISTINCT n.id) FROM {$p}items n JOIN {$p}cves a ON a.item_id=n.id JOIN {$p}cves b ON b.cve=a.cve JOIN {$p}items k ON k.id=b.item_id WHERE n.source='nvd' AND n.active=1 AND k.source='kev' AND k.active=1");
 cdra_need($overlap===$d['counts']['kev_nvd']&&$overlap<=min($expected['kev'],$expected['nvd']),'chart_overlap_sql_mismatch');
 foreach(['cisa-advisories','cert-eu','msrc'] as $source){$count=(int)$s->db->get_var($s->db->prepare("SELECT COUNT(*) FROM {$p}items WHERE source=%s AND active=1",$source));cdra_need($count===($d['by_source'][$source]??0),'advisory_bar_sql_mismatch');}
 $out=['kpis'=>$expected,'severity'=>$histogram,'counts'=>$d['counts'],'nvd_versions'=>$d['versions'],'generated_utc'=>gmdate('Y-m-d\TH:i:s\Z',$d['generated_at']),'coverage_origin'=>$d['origin'],'checkpoint_utc'=>$d['checkpoint']?gmdate('Y-m-d\TH:i:s\Z',$d['checkpoint']):null,'window'=>$d['window'],'completed'=>$d['completed'],'by_source'=>$d['by_source'],'queue_total'=>$d['queue_total'],'feed_records'=>count($d['feed']),'advisory_feed_records'=>count(array_filter($d['feed'],static fn($r)=>$r['kind']==='advisory')),'health'=>$health,'kpi_sql_match'=>true,'histogram_sql_match'=>true,'feed_sql_match'=>true,'chart_totals'=>$chart_totals,'chart_points_sql_match'=>true,'overlap_sql_match'=>true,'history_complete'=>false];
 $s->query('COMMIT');echo wp_json_encode($out);
}catch(Throwable $e){$s->db->query('ROLLBACK');throw $e;}
