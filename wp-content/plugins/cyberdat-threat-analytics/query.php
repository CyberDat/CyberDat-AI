<?php
/** Read-only Research DB adapter. No source fetches, ingestion, schema or editorial changes. */
defined('ABSPATH') || exit;
function cdta_need($ok){if(!$ok){throw new InvalidArgumentException('Invalid analytics filter.');}}
function cdta_filters($input){
 $allowed=['group','value','date','days','q','sort','page','per_page','revision'];cdta_need(!array_diff(array_keys($input),$allowed));
 $defaults=['group'=>'severity','value'=>'Critical','date'=>'','days'=>'all','q'=>'','sort'=>'date_desc','page'=>1,'per_page'=>20,'revision'=>''];$q=array_merge($defaults,$input);
 foreach($q as $key=>$value){cdta_need(is_string($value)||is_int($value));$q[$key]=(string)$value;}
 $groups=['severity'=>['Critical','High','Medium','Low','None','Unrated'],'overlap'=>['shared','kev_only','nvd_only'],'ransomware'=>['known','not_known'],'advisory'=>['cisa-advisories','cert-eu','msrc'],'day'=>['kev','nvd'],'period'=>['critical','nvd','kev','ransomware']];
 cdta_need(isset($groups[$q['group']])&&in_array($q['value'],$groups[$q['group']],true));cdta_need(in_array($q['days'],['all','7','30','90'],true));
 cdta_need(in_array($q['sort'],['date_desc','date_asc','severity_desc','cvss_desc'],true)&&preg_match('/^[A-Za-z0-9-]{0,32}$/D',$q['q']));
 cdta_need(preg_match('/^[1-9][0-9]{0,2}$/D',$q['page'])&&((int)$q['page'])<=600&&preg_match('/^[1-9][0-9]?$/D',$q['per_page'])&&((int)$q['per_page'])<=50);
 cdta_need($q['revision']===''||preg_match('/^[a-f0-9]{64}$/D',$q['revision']));
 if($q['group']==='day'){$t=strtotime($q['date'].' UTC');cdta_need($q['days']!=='all'&&preg_match('/^\d{4}-\d{2}-\d{2}$/D',$q['date'])&&$t&&gmdate('Y-m-d',$t)===$q['date']);}else{cdta_need($q['date']==='');}
 if($q['group']==='period'){cdta_need($q['days']!=='all');}
 $q['page']=(int)$q['page'];$q['per_page']=(int)$q['per_page'];return $q;
}
function cdta_score($alias='i'){return "CASE WHEN JSON_TYPE(JSON_EXTRACT($alias.payload,'$.assessment.score')) IN ('INTEGER','DOUBLE') THEN CAST(JSON_UNQUOTE(JSON_EXTRACT($alias.payload,'$.assessment.score')) AS DECIMAL(5,2)) ELSE NULL END";}
function cdta_band($score){return "CASE WHEN $score IS NULL THEN 'Unrated' WHEN $score>=9 THEN 'Critical' WHEN $score>=7 THEN 'High' WHEN $score>=4 THEN 'Medium' WHEN $score>0 THEN 'Low' ELSE 'None' END";}
function cdta_date($source,$alias='i'){return $source==='kev'?"JSON_UNQUOTE(JSON_EXTRACT($alias.payload,'$.cisa_original.dateAdded'))":"DATE($alias.published)";}
function cdta_bounds($d,$days){$end=strtotime($d['reference_day'].' UTC');return [gmdate('Y-m-d',$end-((int)$days-1)*86400),gmdate('Y-m-d',$end),gmdate('Y-m-d H:i:s',(int)$d['generated_at'])];}
function cdta_where($q,$d,$p,$db){
 $where=['i.active=1'];$params=[];$g=$q['group'];$v=$q['value'];$source='nvd';$score=cdta_score();
 $shared="EXISTS (SELECT 1 FROM {$p}cves a JOIN {$p}cves b ON b.cve=a.cve JOIN {$p}items k ON k.id=b.item_id WHERE a.item_id=i.id AND k.source='kev' AND k.active=1)";
 if($g==='severity'){$where[]="i.source='nvd'";$where[]=cdta_band($score).'=%s';$params[]=$v;}
 elseif($g==='overlap'){
  if($v==='kev_only'){$source='kev';$where[]="i.source='kev'";$where[]="NOT EXISTS (SELECT 1 FROM {$p}cves a JOIN {$p}cves b ON b.cve=a.cve JOIN {$p}items n ON n.id=b.item_id WHERE a.item_id=i.id AND n.source='nvd' AND n.active=1)";}
  else{$where[]="i.source='nvd'";$where[]=($v==='nvd_only'?'NOT ':'').$shared;}
 }
 elseif($g==='ransomware'){$source='kev';$where[]="i.source='kev'";$where[]="COALESCE(JSON_UNQUOTE(JSON_EXTRACT(i.payload,'$.cisa_original.knownRansomwareCampaignUse')),'')".($v==='known'?'=':'<>')."'Known'";}
 elseif($g==='advisory'){$source=$v;$where[]='i.source=%s';$params[]=$v;}
 elseif($g==='day'){$source=$v;$where[]='i.source=%s';$params[]=$v;$where[]=cdta_date($source).'=%s';$params[]=$q['date'];}
 elseif($g==='period'){$source=in_array($v,['kev','ransomware'],true)?'kev':'nvd';$where[]='i.source=%s';$params[]=$source;if($v==='critical'){$where[]="$score BETWEEN 9 AND 10";}if($v==='ransomware'){$where[]="JSON_UNQUOTE(JSON_EXTRACT(i.payload,'$.cisa_original.knownRansomwareCampaignUse'))='Known'";}}
 if($q['days']!=='all'){[$start,$end,$cutoff]=cdta_bounds($d,(int)$q['days']);$date=cdta_date($source);$where[]="$date BETWEEN %s AND %s";$params[]=$start;$params[]=$end;if($g==='day'){cdta_need($q['date']>=$start&&$q['date']<=$end);}}
 if(in_array($g,['period','day'],true)){$where[]="i.published<=%s";$params[]=gmdate('Y-m-d H:i:s',(int)$d['generated_at']);}
 // For KEV, dateAdded is authoritative; never substitute source/import publication time.
 if($source==='kev'&&in_array($g,['period','day'],true)){array_pop($where);array_pop($params);$where[]=cdta_date('kev').'<=%s';$params[]=$d['reference_day'];}
 if($q['q']!==''){$where[]="EXISTS (SELECT 1 FROM {$p}cves cvematch WHERE cvematch.item_id=i.id AND cvematch.cve LIKE %s)";$params[]=strtoupper($q['q']).'%';}
 $sql=implode(' AND ',$where);return [$params?$db->prepare($sql,...$params):$sql,$source];
}
function cdta_snapshot($fn,$expected=''){
 global $wpdb;cdta_need(cdta_staging());$p=$wpdb->prefix.'cdra_';$previous=$wpdb->suppress_errors(true);$lock='cdra_'.substr(hash('sha256',DB_NAME.$p),0,32);
 try{
  if((int)$wpdb->get_var($wpdb->prepare('SELECT IS_FREE_LOCK(%s)',$lock))!==1){throw new RuntimeException('updating');}
  if($wpdb->query('SET TRANSACTION READ ONLY')===false||$wpdb->query('START TRANSACTION WITH CONSISTENT SNAPSHOT')===false){throw new RuntimeException('database');}
  $text=$wpdb->get_var($wpdb->prepare("SELECT payload FROM {$p}state WHERE state_key=%s",'dashboard_v1'));$d=json_decode($text??'null',true,64,JSON_THROW_ON_ERROR);
  if(!is_array($d)||($d['schema']??0)!==1){throw new RuntimeException('unavailable');}$revision=hash('sha256',$text);if($expected!==''&&!hash_equals($revision,$expected)){throw new UnexpectedValueException('revision');}
  $result=$fn($wpdb,$p,$d,$revision);if($wpdb->last_error){throw new RuntimeException('database');}
  if((int)$wpdb->get_var($wpdb->prepare('SELECT IS_FREE_LOCK(%s)',$lock))!==1){throw new RuntimeException('updating');}
  $wpdb->query('COMMIT');return $result;
 }catch(Throwable $e){$wpdb->query('ROLLBACK');throw $e;}finally{$wpdb->suppress_errors($previous);}
}
function cdta_periods($projection=null){
 if(!cdta_staging()){return null;}$projection=$projection??cyberdat_research_dashboard();if(!$projection){return null;}
 // Health fields are intentionally excluded; aggregation revision changes on every completed projection.
 $signature=hash('sha256',wp_json_encode([$projection['generated_at'],$projection['counts'],$projection['chart_series'],$projection['versions']]));$cached=get_transient('cdta_periods_v1');
 if(is_array($cached)&&($cached['signature']??'')===$signature){return $cached['data'];}
 try{$model=cdta_snapshot(static function($db,$p,$d,$revision){
  $out=['revision'=>$revision,'reference_day'=>$d['reference_day'],'generated_at'=>$d['generated_at'],'periods'=>[]];
  [$oldest,$end,$cutoff]=cdta_bounds($d,90);$day="CASE WHEN i.source='kev' THEN ".cdta_date('kev')." ELSE DATE(i.published) END";$score=cdta_score();
  $sql=$db->prepare("SELECT i.source,$day AS day,COUNT(*) AS n,SUM(CASE WHEN $score BETWEEN 9 AND 10 THEN 1 ELSE 0 END) AS critical,SUM(CASE WHEN JSON_UNQUOTE(JSON_EXTRACT(i.payload,'$.cisa_original.knownRansomwareCampaignUse'))='Known' THEN 1 ELSE 0 END) AS ransomware FROM {$p}items i WHERE i.active=1 AND i.source IN ('kev','nvd') AND $day BETWEEN %s AND %s AND (i.source='kev' OR i.published<=%s) GROUP BY i.source,day",$oldest,$end,$cutoff);
  $daily=$db->get_results($sql,ARRAY_A);if(!is_array($daily)){throw new RuntimeException('database');}
  foreach([7,30,90] as $days){[$start,$end]=cdta_bounds($d,$days);$values=['critical'=>0,'nvd'=>0,'kev'=>0,'ransomware'=>0];
   foreach($daily as $row){if($row['day']<$start||$row['day']>$end){continue;}if($row['source']==='nvd'){$values['nvd']+=(int)$row['n'];$values['critical']+=(int)$row['critical'];}else{$values['kev']+=(int)$row['n'];$values['ransomware']+=(int)$row['ransomware'];}}
   $out['periods'][$days]=['start'=>$start,'end'=>$end,'counts'=>$values];
  }
  return $out;
 });
 if($model['generated_at']!==$projection['generated_at']){return null;}set_transient('cdta_periods_v1',['signature'=>$signature,'data'=>$model],600);return $model;
 }catch(Throwable $e){return null;}
}
function cdta_records($q){return cdta_snapshot(static function($db,$p,$d,$revision)use($q){
 [$where,$source]=cdta_where($q,$d,$p,$db);$score=cdta_score();$date=$source==='kev'?cdta_date('kev'):'i.published';
 $rank="CASE WHEN $score IS NULL THEN 0 WHEN $score>=9 THEN 5 WHEN $score>=7 THEN 4 WHEN $score>=4 THEN 3 WHEN $score>0 THEN 2 ELSE 1 END";
 $orders=['date_desc'=>"$date DESC,i.id DESC",'date_asc'=>"$date ASC,i.id ASC",'severity_desc'=>"$rank DESC,$date DESC,i.id DESC",'cvss_desc'=>"$score DESC,$date DESC,i.id DESC"];
 $total=(int)$db->get_var("SELECT COUNT(*) FROM {$p}items i WHERE $where");$limit=$q['per_page'];$offset=($q['page']-1)*$limit;
 $sql="SELECT i.source,i.source_id,i.canonical_url,i.published,LEFT(JSON_UNQUOTE(JSON_EXTRACT(i.payload,'$.original_title')),2048) AS title,LEFT(JSON_UNQUOTE(JSON_EXTRACT(i.payload,'$.summary')),600) AS summary,JSON_EXTRACT(i.payload,'$.assessment') AS assessment,".cdta_date('kev')." AS date_added FROM {$p}items i WHERE $where ORDER BY ".$orders[$q['sort']].$db->prepare(' LIMIT %d OFFSET %d',$limit,$offset);
 $rows=$db->get_results($sql,ARRAY_A);if(!is_array($rows)){throw new RuntimeException('database');}$items=[];
 foreach($rows as $row){$metric=json_decode($row['assessment']??'null',true);$score=is_numeric($metric['score']??null)?(float)$metric['score']:null;$label=$score===null?'Unrated':($score>=9?'Critical':($score>=7?'High':($score>=4?'Medium':($score>0?'Low':'None'))));$url=$row['canonical_url'];$u=wp_parse_url($url);$hosts=cdra_sources()[$row['source']]['hosts'];
  if(($u['scheme']??'')!=='https'||!in_array(strtolower($u['host']??''),$hosts,true)||isset($u['user'])||isset($u['pass'])||isset($u['port'])){throw new RuntimeException('source_url');}
  $items[]=['id'=>$row['source_id'],'title'=>$row['title'],'description'=>$row['summary'],'source'=>$row['source'],'source_name'=>cdra_sources()[$row['source']]['name'],'url'=>$url,'published'=>$row['published'],'date_added'=>$row['source']==='kev'?$row['date_added']:null,'score'=>$score,'cvss_version'=>$metric['version']??null,'severity'=>$label];
 }
 return ['revision'=>$revision,'generated_at'=>$d['generated_at'],'total'=>$total,'page'=>$q['page'],'per_page'=>$limit,'pages'=>(int)ceil($total/$limit),'items'=>$items,'filter'=>$q,'scope'=>'Partial local NVD; absent from local NVD is not absent globally; absent from KEV does not prove no exploitation.'];
 },$q['revision']);}
