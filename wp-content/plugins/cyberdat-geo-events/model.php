<?php
defined('ABSPATH') || exit;
function cdgeo_need($condition){if(!$condition){throw new InvalidArgumentException('Invalid geo data');}}
function cdgeo_sources(){
 // Only reviewed PHP connectors may register a source. No sources are connected now.
 $input=apply_filters('cyberdat_geo_sources',[]);$out=[];
 if(!is_array($input)){return [];}
 foreach(array_slice($input,0,10,true) as $id=>$source){
  if(!is_string($id)||!preg_match('/^[a-z][a-z0-9-]{0,31}$/D',$id)||!is_array($source)||!is_string($source['name']??null)||strlen($source['name'])>80||!is_array($source['hosts']??null)){continue;}
  $hosts=array_filter($source['hosts'],static fn($h)=>is_string($h)&&preg_match('/^(?:[a-z0-9-]+\.)+[a-z]{2,63}$/D',$h)&&!str_ends_with($h,'.local')&&!str_ends_with($h,'.internal')&&!str_ends_with($h,'.localhost'));
  if($hosts){$out[$id]=['name'=>$source['name'],'hosts'=>array_values($hosts)];}
 }
 return $out;
}
function cdgeo_types(){return ['malware','intrusion','exposure','incident','other'];}
function cdgeo_validate_event($event,$sources,$now=null){
 $now=$now??time();cdgeo_need(is_array($event)&&!array_key_exists('source_ip',$event)&&!array_key_exists('target_ip',$event));
 foreach(['event_id','source','event_type','observed_at','country','region','latitude','longitude','geo_type','confidence','evidence_url','verification_status','display_authorized'] as $key){cdgeo_need(array_key_exists($key,$event));}
 cdgeo_need(is_string($event['event_id'])&&preg_match('/^[A-Za-z0-9._:-]{1,128}$/D',$event['event_id'])&&isset($sources[$event['source']])&&in_array($event['event_type'],cdgeo_types(),true));
 $date=DateTimeImmutable::createFromFormat('!Y-m-d\TH:i:s\Z',$event['observed_at'],new DateTimeZone('UTC'));cdgeo_need($date&&$date->format('Y-m-d\TH:i:s\Z')===$event['observed_at']&&$date->getTimestamp()<=$now&&$date->getTimestamp()>=946684800);
 cdgeo_need(is_string($event['country'])&&preg_match('/^[A-Z]{2}$/D',$event['country'])&&is_string($event['region'])&&strlen($event['region'])<=80&&!preg_match('/[<>\x00-\x1f]/',$event['region']));
 foreach(['latitude'=>90,'longitude'=>180] as $key=>$bound){cdgeo_need((is_int($event[$key])||is_float($event[$key]))&&is_finite((float)$event[$key])&&abs($event[$key])<=$bound);$event[$key]=round($event[$key],1);}
 cdgeo_need(in_array($event['geo_type'],['country_centroid','region_centroid','reported_area','sensor_location'],true)&&in_array($event['confidence'],['low','medium','high'],true)&&in_array($event['verification_status'],['pending','verified','rejected'],true)&&is_bool($event['display_authorized']));
 $url=parse_url($event['evidence_url']);cdgeo_need(is_array($url)&&($url['scheme']??'')==='https'&&in_array($url['host']??'',$sources[$event['source']]['hosts'],true)&&!isset($url['user'])&&!isset($url['pass'])&&!isset($url['port'])&&!isset($url['query'])&&!isset($url['fragment'])&&strlen($event['evidence_url'])<=2048&&!preg_match('/[\x00-\x20]/',$event['evidence_url']));
 // Target location is optional, never inferred. Reuse the same coarse representation only.
 $target=$event['target_location']??null;
 if($target!==null){cdgeo_need(is_array($target)&&array_keys($target)===['country','latitude','longitude']&&is_string($target['country'])&&preg_match('/^[A-Z]{2}$/D',$target['country']));foreach(['latitude'=>90,'longitude'=>180] as $key=>$bound){cdgeo_need(is_numeric($target[$key])&&is_finite((float)$target[$key])&&abs((float)$target[$key])<=$bound);$target[$key]=round((float)$target[$key],1);}}
 return array_intersect_key(array_merge($event,['target_location'=>$target]),array_flip(['event_id','source','event_type','observed_at','country','region','latitude','longitude','geo_type','confidence','evidence_url','verification_status','display_authorized','target_location']));
}
function cdgeo_filters($input,$sources){
 $out=['event_type'=>'all','days'=>30,'source'=>'all','page'=>1,'per_page'=>100,'zoom'=>1,'format'=>'clusters'];
 foreach($out as $key=>$default){if(!isset($input[$key])){continue;}$v=$input[$key];cdgeo_need(is_scalar($v));
  if(in_array($key,['days','page','per_page','zoom'],true)){cdgeo_need(preg_match('/^\d{1,3}$/D',(string)$v));$out[$key]=(int)$v;}else{$out[$key]=(string)$v;}
 }
 cdgeo_need(in_array($out['event_type'],array_merge(['all'],cdgeo_types()),true)&&in_array($out['source'],array_merge(['all'],array_keys($sources)),true)&&in_array($out['days'],[7,30,90],true)&&$out['page']>=1&&$out['page']<=10&&$out['per_page']>=1&&$out['per_page']<=100&&$out['zoom']>=1&&$out['zoom']<=6&&in_array($out['format'],['events','clusters'],true));return $out;
}
function cdgeo_project($latitude,$longitude){return [($longitude+180)*1000/360,(90-$latitude)*500/180];}
function cdgeo_clusters($events,$zoom){
 $cell=80/(2**($zoom-1));$buckets=[];
 foreach($events as $event){[$x,$y]=cdgeo_project($event['latitude'],$event['longitude']);$key=floor($x/$cell).':'.floor($y/$cell);$buckets[$key]??=['count'=>0,'latitude'=>0,'longitude'=>0,'events'=>[]];$bucket=&$buckets[$key];$bucket['count']++;$bucket['latitude']+=$event['latitude'];$bucket['longitude']+=$event['longitude'];if(count($bucket['events'])<5){$bucket['events'][]=$event;}unset($bucket);}
 ksort($buckets,SORT_STRING);foreach($buckets as &$bucket){$bucket['latitude']=round($bucket['latitude']/$bucket['count'],1);$bucket['longitude']=round($bucket['longitude']/$bucket['count'],1);}unset($bucket);return array_values($buckets);
}
