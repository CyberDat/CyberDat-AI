<?php
defined('ABSPATH') || exit;
function cdra_text($value,$limit=16384){cdra_need(is_string($value)&&strlen($value)<=$limit&&!preg_match('/[\x00-\x08\x0b\x0c\x0e-\x1f]/',$value),'invalid_text');return $value;}
function cdra_url($url,$hosts=null){
 cdra_need(is_string($url)&&strlen($url)<=2048,'invalid_url');$p=wp_parse_url($url);
 cdra_need(is_array($p)&&($p['scheme']??'')==='https'&&!isset($p['user'],$p['pass'])&&!isset($p['user'])&&!isset($p['pass'])&&(!isset($p['port'])||$p['port']===443)&&!empty($p['host']),'invalid_url');
 $host=strtolower($p['host']);cdra_need(!filter_var($host,FILTER_VALIDATE_IP)&&preg_match('/^[a-z0-9.-]+$/D',$host)&&str_contains($host,'.'),'invalid_url_host');
 if($hosts!==null){cdra_need(in_array($host,$hosts,true),'unapproved_source_link');}
 $query=[];if(isset($p['query'])){parse_str($p['query'],$query);foreach($query as $key=>$value){if(str_starts_with(strtolower($key),'utm_')||in_array($key,['fbclid','gclid'],true)){unset($query[$key]);}}ksort($query);}
 return 'https://'.$host.($p['path']??'/').($query?'?'.http_build_query($query,'','&',PHP_QUERY_RFC3986):'');
}
function cdra_base($source,$id,$url,$title,$summary,$published,$updated,$cves=[]){
 $spec=cdra_sources()[$source];$cves=array_values(array_unique($cves));sort($cves,SORT_STRING);
 return ['source'=>$source,'source_name'=>$spec['name'],'source_id'=>cdra_text($id,2048),'canonical_url'=>cdra_url($url,$spec['hosts']),'original_title'=>cdra_text($title,2048),'summary'=>cdra_text($summary),
 'published'=>$published,'source_updated'=>$updated,'cve_ids'=>$cves,'assessment'=>null,'assessments'=>[],'cwe'=>[],'references'=>[],'vendor'=>null,'product'=>null,'kev_confirmed'=>false,'source_url'=>$spec['url']];
}
function cdra_kev($body){
 $validated=cdra_kev_validate($body);cdra_need(!is_wp_error($validated),'kev_schema');
 $raw=json_decode($body,true,64,JSON_THROW_ON_ERROR);cdra_need($validated['count']>0,'kev_empty');unset($validated);$rows=[];$catalog=[];
 foreach($raw['vulnerabilities'] as $row){
  foreach(['shortDescription','requiredAction','dueDate'] as $key){cdra_need(array_key_exists($key,$row),'kev_required_field');cdra_text($row[$key],$key==='notes'?16384:8192);}
  cdra_need(cdra_kev_day($row['dueDate'])!==false,'kev_due_date');
  foreach(['notes','forensicTriage'] as $optional){if(isset($row[$optional])){cdra_text($row[$optional]);}}
  if(isset($row['cwes'])){cdra_need(is_array($row['cwes'])&&array_is_list($row['cwes'])&&count($row['cwes'])<=128,'kev_cwe');foreach($row['cwes'] as $cwe){cdra_need(is_string($cwe)&&preg_match('/^CWE-\d+$/D',$cwe),'kev_cwe');}}
  $item=cdra_base('kev',$row['cveID'],'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext='.$row['cveID'],$row['vulnerabilityName'],$row['shortDescription'],$row['dateAdded'].'T00:00:00Z',$row['dateAdded'].'T00:00:00Z',[$row['cveID']]);
  $item['catalog_release']=$raw['dateReleased'];$item['source_updated_basis']='dateAdded; no per-entry modification timestamp supplied';$item['vendor']=$row['vendorProject'];$item['product']=$row['product'];$item['kev_confirmed']=true;$item['cwe']=$row['cwes']??[];$item['cisa_original']=$row;
  $rows[]=$item;if(!isset($row['knownRansomwareCampaignUse'])){$row['knownRansomwareCampaignUse']='Not provided';}$catalog[]=$row;
 }
 usort($catalog,static fn($a,$b)=>strcmp($b['dateAdded'],$a['dateAdded'])?:strcmp($b['cveID'],$a['cveID']));
 return ['rows'=>$rows,'catalog'=>['catalogVersion'=>$raw['catalogVersion'],'dateReleased'=>$raw['dateReleased'],'count'=>count($catalog),'vulnerabilities'=>$catalog]];
}
function cdra_nvd_page($body,$query){
 try{$raw=json_decode($body,true,64,JSON_THROW_ON_ERROR);}catch(Throwable $e){throw new CDRA_Error('nvd_json');}
 cdra_need(is_array($raw)&&($raw['format']??'')==='NVD_CVE'&&($raw['version']??'')==='2.0','nvd_envelope');
 foreach(['totalResults','resultsPerPage','startIndex'] as $key){cdra_need(isset($raw[$key])&&is_int($raw[$key])&&$raw[$key]>=0,'nvd_pagination');}
 cdra_need($raw['startIndex']===(int)($query['startIndex']??0)&&$raw['resultsPerPage']<=50&&$raw['totalResults']<=1000000&&is_array($raw['vulnerabilities']??null)&&array_is_list($raw['vulnerabilities'])&&count($raw['vulnerabilities'])<=50,'nvd_pagination');
 cdra_need(count($raw['vulnerabilities'])+$raw['startIndex']<=$raw['totalResults']&&($raw['vulnerabilities']||$raw['totalResults']===0),'nvd_partial_page');
 $rows=[];$seen=[];
 foreach($raw['vulnerabilities'] as $wrapper){
  $cve=$wrapper['cve']??[];$id=$cve['id']??'';cdra_need(cdra_nvd_id($id)&&!isset($seen[$id]),'nvd_duplicate');$seen[$id]=true;
  foreach(['published','lastModified'] as $field){cdra_need(cdra_time($cve[$field]??null)<=time()+300,'nvd_future_date');}
  if(isset($query['lastModStartDate'])){cdra_need(cdra_time($cve['lastModified'])>=cdra_time($query['lastModStartDate'])&&cdra_time($cve['lastModified'])<=cdra_time($query['lastModEndDate']),'nvd_window');}
  if(isset($query['cveIds'])){cdra_need(in_array($id,explode(',',$query['cveIds']),true),'nvd_id_mismatch');}
  $one=['version'=>'2.0','totalResults'=>1,'startIndex'=>0,'vulnerabilities'=>[$wrapper]];
  $rejected=($cve['vulnStatus']??'')==='Rejected';
  $parsed=$rejected?['description'=>'NVD record rejected.','assessment'=>null]:cdra_nvd_parse(cdra_json($one),$id);
  cdra_need(!is_wp_error($parsed),'nvd_cvss_schema');
  $item=cdra_base('nvd',$id,'https://nvd.nist.gov/vuln/detail/'.$id,$id,$parsed['description'],$cve['published'],$cve['lastModified'],[$id]);
  $item['assessment']=$parsed['assessment'];$item['vuln_status']=$cve['vulnStatus']??'Unknown';
  if(!$rejected){foreach(($cve['metrics']??[]) as $kind=>$metrics){if(!in_array($kind,['cvssMetricV40','cvssMetricV31','cvssMetricV30','cvssMetricV2'],true)){continue;}foreach($metrics as $metric){$single=$one;$single['vulnerabilities'][0]['cve']['metrics']=[$kind=>[$metric]];$a=cdra_nvd_parse(cdra_json($single),$id);cdra_need(!is_wp_error($a)&&$a['assessment'],'nvd_cvss_schema');$assessment=$a['assessment'];$assessment['source_severity']=$metric['cvssData']['baseSeverity']??($metric['baseSeverity']??null);if($assessment['version']!=='2.0'&&$assessment['source_severity']==='NONE'){$assessment['severity']='None';}$selected=$item['assessment'];if($selected&&$assessment['version']===$selected['version']&&$assessment['source']===$selected['source']&&$assessment['type']===$selected['type']&&$assessment['vector']===$selected['vector']&&$assessment['score']===$selected['score']){$item['assessment']=$assessment;}$item['assessments'][]=$assessment;}}}
  usort($item['assessments'],static fn($a,$b)=>strcmp(cdra_json($a),cdra_json($b)));
  foreach(($cve['weaknesses']??[]) as $weakness){foreach(($weakness['description']??[]) as $d){if(is_string($d['value']??null)&&preg_match('/^CWE-\d+$/D',$d['value'])){$item['cwe'][]=$d['value'];}}}$item['cwe']=array_values(array_unique($item['cwe']));sort($item['cwe']);
  foreach(array_slice($cve['references']??[],0,100) as $reference){try{$item['references'][]=cdra_url($reference['url']??'');}catch(CDRA_Error $e){/* Untrusted/non-HTTPS references are not actionable links. */}}
  $rows[]=$item;
 }
 return ['rows'=>$rows,'total'=>$raw['totalResults'],'index'=>$raw['startIndex'],'count'=>count($rows)];
}
function cdra_feed($body,$source){
 cdra_need(strlen($body)<=2097152&&!preg_match('/<!\s*(?:DOCTYPE|ENTITY)/i',$body),'xml_entities_rejected');
 $old=libxml_use_internal_errors(true);$xml=simplexml_load_string($body,'SimpleXMLElement',LIBXML_NONET|LIBXML_NOCDATA);libxml_clear_errors();libxml_use_internal_errors($old);
 cdra_need($xml!==false,'xml_parse');$entries=$xml->channel->item??($xml->entry??[]);$out=[];$seen=[];
 foreach($entries as $entry){
  if(count($out)>=25){break;}
  $url=(string)$entry->link;if($url===''){$url=(string)$entry->link['href'];}
  $url=cdra_url($url,cdra_sources()[$source]['hosts']);$id=(string)($entry->guid??$entry->id);if($id===''){$id=$url;}
  cdra_need(!isset($seen[$id]),'feed_duplicate');$seen[$id]=true;
  $title=html_entity_decode(wp_strip_all_tags((string)$entry->title),ENT_QUOTES,'UTF-8');$summary=html_entity_decode(wp_strip_all_tags((string)($entry->description??$entry->summary??$entry->content)),ENT_QUOTES,'UTF-8');
  $date=(string)($entry->pubDate??$entry->published??$entry->updated);$at=$date!==''?strtotime($date):false;cdra_need($at!==false&&$at<=time()+300,'feed_date');
  $updated=(string)$entry->updated;$updated_at=$updated!==''?strtotime($updated):$at;cdra_need($updated_at!==false&&$updated_at<=time()+300,'feed_date');
  preg_match_all('/\bCVE-\d{4}-\d{4,19}\b/',$title.' '.$summary,$matches);
  $item=cdra_base($source,$id,$url,$title,mb_substr($summary,0,8000),gmdate('Y-m-d\TH:i:s\Z',$at),gmdate('Y-m-d\TH:i:s\Z',$updated_at),$matches[0]);$item['references']=[$url];$out[]=$item;
 }
 cdra_need(count($out)>0,'feed_empty');return $out;
}
