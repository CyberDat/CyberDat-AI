<?php
defined('ABSPATH') || exit;
function cdra_discovery_query($source,$q){
 $spec=cdra_spec($source);if($spec['format']==='rss'){cdra_need(!$q,'query_rejected');return '';}
 if($spec['format']==='arxiv'){
  cdra_need(array_keys($q)===['search_query','start','max_results','sortBy','sortOrder']&&$q['search_query']==='cat:cs.CR'&&is_int($q['start'])&&$q['start']>=0&&$q['start']<=500&&$q['max_results']===25&&$q['sortBy']==='lastUpdatedDate'&&$q['sortOrder']==='descending','academic_query');
 }elseif($spec['format']==='crossref'){
  cdra_need(array_keys($q)===['query','filter','rows','cursor','sort','order']&&$q['query']==='cybersecurity'&&preg_match('/^from-index-date:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2},until-index-date:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/D',$q['filter'])&&$q['rows']===25&&is_string($q['cursor'])&&strlen($q['cursor'])<=4096&&!preg_match('/[\x00-\x20]/',$q['cursor'])&&$q['sort']==='indexed'&&$q['order']==='asc','academic_query');
 }else{throw new CDRA_Error('academic_query');}
 return '?'.http_build_query($q,'','&',PHP_QUERY_RFC3986);
}
function cdra_discovery_ingest($service,$source){
 $s=$service->store;$spec=cdra_spec($source);cdra_need(cdra_discovery_enabled($source,$s),'source_disabled');$health=$s->get('health:'.$source,[]);$q=[];$window=null;
 if($spec['format']!=='rss'){
  $window=$s->get('discovery_window:'.$source);if(!$window){$end=time()-600;$window=['start'=>$s->get('discovery_checkpoint:'.$source,$end-86400)-3600,'end'=>$end,'offset'=>0,'cursor'=>'*','seen'=>[]];$s->put('discovery_window:'.$source,$window);}
  if($spec['format']==='arxiv'){$q=['search_query'=>'cat:cs.CR','start'=>$window['offset'],'max_results'=>25,'sortBy'=>'lastUpdatedDate','sortOrder'=>'descending'];}
  else{$q=['query'=>'cybersecurity','filter'=>'from-index-date:'.gmdate('Y-m-d\TH:i:s',$window['start']).',until-index-date:'.gmdate('Y-m-d\TH:i:s',$window['end']),'rows'=>25,'cursor'=>$window['cursor'],'sort'=>'indexed','order'=>'asc'];}
 }
 $response=$service->request($source,$q,$s->count($source)&&!$window?$health:[]);
 if($response['status']===304){cdra_need($s->count($source)>0,'feed_304_without_cache');$service->success($source,$response,false);return;}
 $rows=cdra_discovery_parse($source,$response['body']);$stats=['discovered'=>count($rows),'inserted'=>0,'duplicates'=>0,'updated'=>0];$done=count($rows)<25;$next=null;$api_count=count($rows);
 if($spec['format']==='crossref'){$raw=json_decode($response['body'],true,64,JSON_THROW_ON_ERROR);$api_count=count($raw['message']['items']);$done=$api_count<25;$stats['skipped_missing_publication']=$api_count-count($rows);$next=$raw['message']['next-cursor']??null;cdra_need($done||is_string($next)&&$next!==$window['cursor'],'academic_cursor');}
 if($spec['format']==='arxiv'){
  foreach($rows as $row){if(cdra_time($row['source_updated'])<$window['start']){$done=true;}}
  cdra_need($window['offset']<=500,'academic_window_capacity');
 }
 $ds=new CDRA_Discovery_Store($s);
 $s->transaction(function()use($service,$s,$ds,$source,$rows,$response,$window,$done,$next,$spec,$api_count,&$stats){
  foreach($rows as $record){
   if($window&&$spec['format']==='arxiv'&&cdra_time($record['source_updated'])<$window['start']){continue;}
   if($window&&isset($window['seen'][$record['source_id']])){throw new CDRA_Error('academic_pagination_shift');}
   $result=$ds->persist($record);$stats[$result['inserted']?'inserted':($result['duplicate']?'duplicates':'updated')]++;
   if($window){$window['seen'][$record['source_id']]=true;}
   $stats['last_record']=$record['canonical_url'];
  }
  $service->success($source,$response);
  if($window){
   if($done){$s->put('discovery_checkpoint:'.$source,$window['end']);$s->put('discovery_window:'.$source,null);}
   else{$window['offset']+=$api_count;$window['cursor']=$next??'*';cdra_need($window['offset']<=500,'academic_window_capacity');$s->put('discovery_window:'.$source,$window);$h=$s->get('health:'.$source);$h['next_due']=time()+300;$s->put('health:'.$source,$h);}
  }
  $h=$s->get('health:'.$source);$h['discovery_stats']=$stats;$h['connection']=$s->count($source)>0?'ACTIVE':'EMPTY';$h['records_inserted_total']=($h['records_inserted_total']??0)+$stats['inserted'];$h['records_duplicates_total']=($h['records_duplicates_total']??0)+$stats['duplicates'];$h['records_discovered_total']=($h['records_discovered_total']??0)+$stats['discovered'];$s->put('health:'.$source,$h);
 });
}
