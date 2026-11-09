<?php
/** Independent SQL expectations vs adapter, including all 180 daily drill counts. No ingestion. */
cdra_need(cdra_staging()&&cdta_staging(),'staging_only');$s=new CDRA_Store();$db=$s->db;$p=$s->prefix;$d=cyberdat_research_dashboard();$m=cdta_periods($d);cdra_need(is_array($m),'period_model_unavailable');$revision=$m['revision'];
$score="CAST(JSON_UNQUOTE(JSON_EXTRACT(payload,'$.assessment.score')) AS DECIMAL(5,2))";$numeric="JSON_TYPE(JSON_EXTRACT(payload,'$.assessment.score')) IN ('INTEGER','DOUBLE')";$out=[];
foreach([7,30,90] as $days){$start=gmdate('Y-m-d',strtotime($d['reference_day'].' UTC')-($days-1)*86400);$cutoff=gmdate('Y-m-d H:i:s',$d['generated_at']);
 $nvd=$db->get_row($db->prepare("SELECT COUNT(*) AS n,SUM(CASE WHEN $numeric AND $score BETWEEN 9 AND 10 THEN 1 ELSE 0 END) AS critical FROM {$p}items WHERE active=1 AND source='nvd' AND published>=%s AND published<=%s",$start.' 00:00:00',$cutoff),ARRAY_A);
 $date="JSON_UNQUOTE(JSON_EXTRACT(payload,'$.cisa_original.dateAdded'))";$kev=$db->get_row($db->prepare("SELECT COUNT(*) AS n,SUM(CASE WHEN JSON_UNQUOTE(JSON_EXTRACT(payload,'$.cisa_original.knownRansomwareCampaignUse'))='Known' THEN 1 ELSE 0 END) AS ransomware FROM {$p}items WHERE active=1 AND source='kev' AND $date BETWEEN %s AND %s",$start,$d['reference_day']),ARRAY_A);
 $expected=['critical'=>(int)$nvd['critical'],'nvd'=>(int)$nvd['n'],'kev'=>(int)$kev['n'],'ransomware'=>(int)$kev['ransomware']];cdra_need($expected===$m['periods'][$days]['counts'],'period_kpi_sql_mismatch');
 foreach($expected as $key=>$count){$q=cdta_filters(['group'=>'period','value'=>$key,'days'=>$days,'revision'=>$revision,'per_page'=>1]);cdra_need(cdta_records($q)['total']===$count,'period_drill_sql_mismatch');}$out[$days]=['start'=>$start,'end'=>$d['reference_day'],'counts'=>$expected];
}
$checks=[];foreach($d['severity'] as $value=>$count){$r=cdta_records(cdta_filters(['group'=>'severity','value'=>$value,'revision'=>$revision]));cdra_need($r['total']===$count,'severity_drill_mismatch');$checks['severity:'.$value]=$r['total'];}
foreach(['shared'=>$d['counts']['kev_nvd'],'kev_only'=>$d['counts']['kev']-$d['counts']['kev_nvd'],'nvd_only'=>$d['counts']['nvd']-$d['counts']['kev_nvd']] as $value=>$count){$r=cdta_records(cdta_filters(['group'=>'overlap','value'=>$value,'revision'=>$revision]));cdra_need($r['total']===$count,'overlap_drill_mismatch');$checks['overlap:'.$value]=$count;}
foreach(['known'=>$d['counts']['ransomware'],'not_known'=>$d['counts']['kev']-$d['counts']['ransomware']] as $value=>$count){cdra_need(cdta_records(cdta_filters(['group'=>'ransomware','value'=>$value,'revision'=>$revision]))['total']===$count,'ransomware_drill_mismatch');$checks['ransomware:'.$value]=$count;}
foreach(['cisa-advisories','cert-eu','msrc'] as $value){$count=$d['by_source'][$value]??0;cdra_need(cdta_records(cdta_filters(['group'=>'advisory','value'=>$value,'revision'=>$revision]))['total']===$count,'advisory_drill_mismatch');$checks['advisory:'.$value]=$count;}
$point_checks=0;foreach(['kev','nvd'] as $source){foreach($d['chart_series'][$source] as $date=>$count){cdra_need(cdta_records(cdta_filters(['group'=>'day','value'=>$source,'date'=>$date,'days'=>90,'revision'=>$revision,'per_page'=>1]))['total']===$count,'daily_drill_mismatch');$point_checks++;}}
$q=cdta_filters(['group'=>'severity','value'=>'High','revision'=>$revision,'per_page'=>5]);$first=cdta_records($q);$q['page']=2;$second=cdta_records($q);cdra_need(!array_intersect(array_column($first['items'],'id'),array_column($second['items'],'id')),'pagination_duplicates');
foreach(['date_desc','date_asc','severity_desc','cvss_desc'] as $sort){$q['page']=1;$q['sort']=$sort;$r=cdta_records($q);cdra_need(count($r['items'])<=5,'page_limit');
 for($i=1;$i<count($r['items']);$i++){$a=$r['items'][$i-1];$b=$r['items'][$i];
  if($sort==='cvss_desc'){cdra_need($a['score']>=$b['score'],'cvss_sort_mismatch');}
  elseif($sort==='date_asc'){cdra_need($a['published']<=$b['published'],'date_asc_mismatch');}
  else{cdra_need($a['published']>=$b['published'],'date_desc_or_band_sort_mismatch');}
 }
}
if($first['items']){$id=$first['items'][0]['id'];$r=cdta_records(cdta_filters(['group'=>'severity','value'=>'High','q'=>$id,'revision'=>$revision]));cdra_need($r['total']===1&&$r['items'][0]['id']===$id,'cve_search_mismatch');}
cdra_need(!$db->last_error,'proof_database_error');echo wp_json_encode(['periods'=>$out,'revision'=>$revision,'chart_counts'=>$checks,'daily_points_checked'=>$point_checks,'pagination_search'=>true,'projection_generated'=>$d['generated_at'],'partial_nvd'=>true]);
