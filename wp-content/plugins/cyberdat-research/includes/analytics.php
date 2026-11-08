<?php
/** Read-model only: source ingestion and editorial workflows remain unchanged. */
defined('ABSPATH') || exit;
function cdra_dashboard_model($rows,$catalog,$state,$now=null){
 $now=$now??time();$day=strtotime(gmdate('Y-m-d',$now).' UTC');$seven=$day-6*86400;$thirty=$day-29*86400;
 $counts=['kev'=>0,'nvd'=>0,'critical'=>0,'high'=>0,'ransomware'=>0,'advisories'=>0,'nvd_7'=>0,'nvd_30'=>0,'kev_7'=>0,'kev_30'=>0,'rated'=>0,'kev_nvd'=>0];
 $severity=array_fill_keys(['Critical','High','Medium','Low','None','Unrated'],0);$versions=[];$days=[];$nvd_days=[];$kev_days=[];$feeds=[];$seen=[];$by_source=[];$nvd_min=null;$nvd_max=null;
 for($i=89;$i>=0;--$i){$date=gmdate('Y-m-d',$day-$i*86400);$nvd_days[$date]=0;$kev_days[$date]=0;if($i<30){$days[$date]=0;}}
 $ransom=[];foreach(($catalog['vulnerabilities']??[]) as $entry){$id=$entry['cveID'];$counts['kev']++;if(($entry['knownRansomwareCampaignUse']??'')==='Known'){$ransom[$id]=true;$counts['ransomware']++;}$date=strtotime($entry['dateAdded'].' UTC');if(isset($kev_days[$entry['dateAdded']])&&$date<=$now){$kev_days[$entry['dateAdded']]++;}if($date>=$seven&&$date<=$now){$counts['kev_7']++;}if($date>=$thirty&&$date<=$now){$counts['kev_30']++;}}
 foreach($rows as $row){
  $source=$row['source'];$by_source[$source]=($by_source[$source]??0)+1;$assessment=$row['assessment']??null;
  $score=is_array($assessment)&&is_numeric($assessment['score']??null)?(float)$assessment['score']:null;
  $label=$score===null?'Unrated':($score>=9?'Critical':($score>=7?'High':($score>=4?'Medium':($score>0?'Low':'None'))));
  $published=strtotime($row['published'].' UTC');
  if($source==='nvd'){
   $publication_day=gmdate('Y-m-d',$published);if(isset($nvd_days[$publication_day])&&$published<=$now){$nvd_days[$publication_day]++;}
   $counts['nvd']++;$severity[$label]++;if($label==='Critical'){$counts['critical']++;}if($label==='High'){$counts['high']++;}if($score!==null){$counts['rated']++;}
   $version=$assessment['version']??'Unrated';$versions[$version]??=array_fill_keys(array_keys($severity),0);$versions[$version][$label]++;
   if($published>=$seven&&$published<=$now){$counts['nvd_7']++;}if($published>=$thirty&&$published<=$now){$counts['nvd_30']++;$date=gmdate('Y-m-d',$published);if(isset($days[$date])){$days[$date]++;}}
   $nvd_min=$nvd_min===null?min($published,$now):min($nvd_min,$published);$nvd_max=$nvd_max===null?$published:max($nvd_max,$published);
   if(!empty($row['kev_confirmed'])){$counts['kev_nvd']++;}
  }elseif($source!=='kev'){$counts['advisories']++;}
  // Bound cache by source, not by combined volume: advisories cannot be crowded out by NVD.
  if(($seen[$source]??0)>=20){continue;}$seen[$source]=($seen[$source]??0)+1;
  $ids=array_values(array_filter($row['cve_ids']??[],static fn($id)=>is_string($id)&&preg_match('/^CVE-\d{4}-\d{4,19}$/D',$id)));$ransomware=(bool)array_intersect_key($ransom,array_fill_keys($ids,true));
  $feeds[]=['id'=>$row['source_id'],'source'=>$source,'kind'=>$source==='nvd'?'cve':($source==='kev'?'kev':'advisory'),'title'=>$row['title'],'summary'=>$row['summary'],'url'=>$row['canonical_url'],'published'=>$row['published'],'source_updated'=>$row['source_updated'],'severity'=>$label,'assessment'=>$assessment,'cve_ids'=>$ids,'kev'=>!empty($row['kev_confirmed']),'ransomware'=>$ransomware];
 }
 usort($feeds,static fn($a,$b)=>strcmp($b['published'],$a['published'])?:strcmp($a['source'],$b['source'])?:strcmp($a['id'],$b['id']));ksort($versions);
 return ['schema'=>1,'generated_at'=>$now,'reference_day'=>gmdate('Y-m-d',$now),'counts'=>$counts,'severity'=>$severity,'versions'=>$versions,'days'=>$days,'chart_series'=>['kev'=>$kev_days,'nvd'=>$nvd_days],'feed'=>$feeds,'by_source'=>$by_source,'source_health'=>$state['source_health'],'catalog_version'=>$catalog['catalogVersion']??null,'catalog_released'=>$catalog['dateReleased']??null,'origin'=>$state['origin'],'checkpoint'=>$state['checkpoint'],'window'=>$state['window'],'completed'=>$state['completed'],'backfill'=>$state['backfill'],'queue_total'=>$state['queue_total'],'publication_min'=>$nvd_min?gmdate('Y-m-d',$nvd_min):null,'publication_max'=>$nvd_max?gmdate('Y-m-d',$nvd_max):null,'feed_limit_per_source'=>20,'historical_nvd_complete'=>false];
}
function cdra_build_dashboard_analytics($store){
 // At most 12,000 indexed records / 5,000 NVD, matching existing hard storage limits.
 // No original payload bodies, credentials or references enter the read-model.
 $sql="SELECT source,source_id,canonical_url,published,source_updated,kev_confirmed,LEFT(JSON_UNQUOTE(JSON_EXTRACT(payload,'$.original_title')),2048) AS title,LEFT(JSON_UNQUOTE(JSON_EXTRACT(payload,'$.summary')),600) AS summary,JSON_EXTRACT(payload,'$.assessment') AS assessment,JSON_EXTRACT(payload,'$.cve_ids') AS cve_ids FROM {$store->prefix}items WHERE active=1 ORDER BY published DESC,id DESC LIMIT 12000";
 $previous=$store->db->suppress_errors(true);
 try{$rows=$store->db->get_results($sql,ARRAY_A);cdra_need(!$store->db->last_error&&is_array($rows),'analytics_database_read');}finally{$store->db->suppress_errors($previous);}
 foreach($rows as &$row){$row['assessment']=json_decode($row['assessment']??'null',true,64,JSON_THROW_ON_ERROR);$row['cve_ids']=json_decode($row['cve_ids']??'[]',true,64,JSON_THROW_ON_ERROR);}unset($row);
 $health=[];foreach(cdra_sources() as $id=>$spec){$health[$id]=$store->get('health:'.$id,[]);}
 $data=cdra_dashboard_model($rows,$store->get('kev_catalog'),['source_health'=>$health,'origin'=>$store->get('nvd_origin'),'checkpoint'=>$store->get('nvd_checkpoint'),'window'=>$store->get('nvd_window'),'completed'=>$store->get('nvd_last_completed_window'),'backfill'=>$store->get('backfill',['status'=>'not_requested']),'queue_total'=>$store->count()]);
 // Page ledgers remain in private state, not in HTML or the lightweight read-model.
 foreach(['window','completed'] as $key){if(is_array($data[$key])){unset($data[$key]['pages']);}}
 cdra_need(strlen(cdra_json($data))<=2097152,'analytics_cache_size');$store->put('dashboard_v1',$data);
}
function cyberdat_research_dashboard(){
 if(!cdra_staging()||!cyberdat_research_active()){return null;}
 try{$store=new CDRA_Store();$data=$store->get('dashboard_v1');if(!is_array($data)||($data['schema']??0)!==1){return null;}foreach(cdra_sources() as $id=>$spec){$data['source_health'][$id]=$store->get('health:'.$id,[]);}return $data;}catch(Throwable $error){return null;}
}
function cdra_dashboard_filters($input){
 $choices=['ti_source'=>array_merge(['all'],array_keys(cdra_sources())),'ti_severity'=>['all','Critical','High','Medium','Low','None','Unrated'],'ti_kind'=>['all','cve','kev','advisory']];$out=[];
 foreach($choices as $key=>$allowed){$value=$input[$key]??'all';$out[$key]=is_string($value)&&in_array($value,$allowed,true)?$value:'all';}return $out;
}
function cdra_dashboard_feed($model,$filters){return array_values(array_filter($model['feed'],static fn($row)=>($filters['ti_source']==='all'||$row['source']===$filters['ti_source'])&&($filters['ti_severity']==='all'||$row['severity']===$filters['ti_severity'])&&($filters['ti_kind']==='all'||$row['kind']===$filters['ti_kind'])));}
