<?php
/** Reviewed 0.5 parsers, now library-only: no I/O, options, jobs or theme dependency. */
defined('ABSPATH') || exit;
function cdra_kev_day($value) {
 if (!is_string($value) || !preg_match('/^\d{4}-\d{2}-\d{2}$/D', $value)) { return false; }
 $date = DateTimeImmutable::createFromFormat('!Y-m-d', $value, new DateTimeZone('UTC'));
 return $date && $date->format('Y-m-d') === $value ? $date->getTimestamp() : false;
}
/** Strict validation of consumed fields; unneeded fields/URLs are discarded. */
function cdra_kev_validate($json, $now = null) {
 $now = $now ?? time();
 if (!is_string($json) || strlen($json) > 4194304) { return new WP_Error('kev_size', 'KEV response exceeds limit.'); }
 try { $data = json_decode($json, true, 32, JSON_THROW_ON_ERROR); }
 catch (Throwable $e) { return new WP_Error('kev_json', 'Invalid KEV JSON.'); }
 if (!is_array($data) || !isset($data['count'],$data['vulnerabilities'],$data['catalogVersion'],$data['dateReleased']) || !is_int($data['count']) || !is_array($data['vulnerabilities']) || !array_is_list($data['vulnerabilities']) || $data['count'] !== count($data['vulnerabilities']) || $data['count'] > 10000 || !is_string($data['catalogVersion']) || !preg_match('/^\d{4}\.\d{2}\.\d{2}$/D',$data['catalogVersion']) || cdra_kev_day(str_replace('.','-',$data['catalogVersion'])) === false || !is_string($data['dateReleased']) || !preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/D',$data['dateReleased'])) {
  return new WP_Error('kev_structure', 'Invalid KEV catalog structure.');
 }
 try { $released = new DateTimeImmutable($data['dateReleased']); }
 catch (Throwable $e) { return new WP_Error('kev_release', 'Invalid catalog release.'); }
 if (cdra_kev_day(substr($data['dateReleased'],0,10)) === false || $released->getTimestamp() > $now + 300 || $released->format('H:i:s') !== substr($data['dateReleased'],11,8)) { return new WP_Error('kev_release', 'Invalid or future catalog release.'); }
 $rows=[];$seen=[];
 foreach ($data['vulnerabilities'] as $row) {
  if (!is_array($row) || !isset($row['cveID'],$row['dateAdded']) || !is_string($row['cveID']) || !preg_match('/^CVE-\d{4}-\d{4,19}$/D',$row['cveID']) || isset($seen[$row['cveID']])) { return new WP_Error('kev_cve', 'Invalid or duplicate CVE.'); }
  $day=cdra_kev_day($row['dateAdded']);
  if ($day === false || $day > cdra_kev_day(gmdate('Y-m-d',$now)) || $day > cdra_kev_day($released->format('Y-m-d'))) { return new WP_Error('kev_date', 'Invalid or future dateAdded.'); }
  foreach (['vendorProject','product','vulnerabilityName'] as $key) {
   if (!isset($row[$key]) || !is_string($row[$key]) || trim($row[$key]) === '' || strlen($row[$key]) > 2048 || preg_match('/[\x00-\x08\x0b\x0c\x0e-\x1f]/',$row[$key])) { return new WP_Error('kev_text','Invalid KEV text.'); }
  }
  $ransom=$row['knownRansomwareCampaignUse'] ?? 'Not provided';
  if (!in_array($ransom,['Known','Unknown','Not provided'],true)) { return new WP_Error('kev_ransomware','Unknown ransomware field value.'); }
  $rows[]=['cveID'=>$row['cveID'],'vendorProject'=>$row['vendorProject'],'product'=>$row['product'],'vulnerabilityName'=>$row['vulnerabilityName'],'dateAdded'=>$row['dateAdded'],'knownRansomwareCampaignUse'=>$ransom];
  $seen[$row['cveID']]=true;
 }
 usort($rows,static function($a,$b){return strcmp($b['dateAdded'],$a['dateAdded']) ?: strcmp($b['cveID'],$a['cveID']);});
 return ['catalogVersion'=>$data['catalogVersion'],'dateReleased'=>$data['dateReleased'],'count'=>count($rows),'vulnerabilities'=>$rows];
}

function cdra_nvd_id($id){return is_string($id) && preg_match('/^CVE-\d{4}-\d{4,19}$/D',$id);}
/** Higher version, NIST source, Primary, source/vector lexical order. Never highest score. */
function cdra_nvd_parse($json,$id){
 if(!cdra_nvd_id($id) || !is_string($json) || strlen($json)>1048576){return new WP_Error('nvd_input','Invalid input or response size.');}
 try{$data=json_decode($json,true,48,JSON_THROW_ON_ERROR);}catch(Throwable $e){return new WP_Error('nvd_json','Invalid JSON.');}
 if(!is_array($data) || ($data['version']??'')!=='2.0' || !isset($data['totalResults'],$data['vulnerabilities']) || !is_int($data['totalResults']) || !is_array($data['vulnerabilities']) || !array_is_list($data['vulnerabilities'])){return new WP_Error('nvd_structure','Invalid NVD envelope.');}
 if($data['totalResults']===0 && $data['vulnerabilities']===[]){return new WP_Error('nvd_not_found','Not available from NVD; vulnerability existence is not disproven.');}
 if($data['totalResults']!==1 || count($data['vulnerabilities'])!==1 || ($data['startIndex']??0)!==0){return new WP_Error('nvd_structure','Expected one specific CVE.');}
 $cve=$data['vulnerabilities'][0]['cve']??null;
 if(!is_array($cve) || ($cve['id']??'')!==$id || !isset($cve['descriptions']) || !is_array($cve['descriptions']) || !is_array($cve['metrics']??[])){return new WP_Error('nvd_cve','Mismatched CVE or malformed record.');}
 if(($cve['vulnStatus']??'')==='Rejected'){return new WP_Error('nvd_rejected','NVD record rejected; retain KEV context.');}
 $descriptions=[];foreach($cve['descriptions'] as $d){if(!is_array($d) || !isset($d['lang'],$d['value']) || !is_string($d['value']) || strlen($d['value'])>16384){return new WP_Error('nvd_description','Invalid description.');}if($d['lang']==='en'){$descriptions[]=$d['value'];}}sort($descriptions,SORT_STRING);
 $choice=null;
 foreach(['cvssMetricV40'=>'4.0','cvssMetricV31'=>'3.1','cvssMetricV30'=>'3.0','cvssMetricV2'=>'2.0'] as $key=>$version){
  if(!isset($cve['metrics'][$key])){continue;}
  $list=$cve['metrics'][$key];if(!is_array($list) || !array_is_list($list) || count($list)>128){return new WP_Error('nvd_metric','Invalid metrics.');}
  $valid=[];
  foreach($list as $metric){
   $cv=$metric['cvssData']??[];$score=$cv['baseScore']??null;$source=$metric['source']??null;$type=$metric['type']??null;$vector=$cv['vectorString']??null;
   if(($cv['version']??'')!==$version || (!is_float($score) && !is_int($score)) || !is_finite((float)$score) || $score<0 || $score>10 || abs($score*10-round($score*10))>0.000001 || !is_string($source) || trim($source)==='' || strlen($source)>256 || !in_array($type,['Primary','Secondary'],true) || !is_string($vector) || strlen($vector)>1024 || !preg_match($version==='2.0'?'~^AV:[A-Z]/~D':'~^CVSS:'.preg_quote($version,'~').'/~D',$vector)){return new WP_Error('nvd_metric','Invalid CVSS assessment.');}
   $severity='Unclassified';$raw=$cv['baseSeverity']??($version==='2.0'?($metric['baseSeverity']??null):null);
   if($raw!==null && !in_array($raw,['NONE','LOW','MEDIUM','HIGH','CRITICAL'],true)){return new WP_Error('nvd_metric','Invalid severity.');}
   if($version!=='2.0' && $raw!==null){
    $expected=$score===0 || $score===0.0?'NONE':($score<4?'LOW':($score<7?'MEDIUM':($score<9?'HIGH':'CRITICAL')));
    if($raw!==$expected){return new WP_Error('nvd_metric','Inconsistent score/severity.');}
    if($raw!=='NONE'){$severity=ucfirst(strtolower($raw));}
   }
   $valid[]=['version'=>$version,'score'=>(float)$score,'severity'=>$severity,'source'=>$source,'type'=>$type,'vector'=>$vector,'legacy_severity'=>$version==='2.0'?$raw:null];
  }
  usort($valid,static function($a,$b){return ((strtolower($a['source'])==='nvd@nist.gov'?0:1) <=> (strtolower($b['source'])==='nvd@nist.gov'?0:1)) ?: (($a['type']==='Primary'?0:1) <=> ($b['type']==='Primary'?0:1)) ?: strcmp(strtolower($a['source']),strtolower($b['source'])) ?: strcmp($a['source'],$b['source']) ?: strcmp($a['vector'],$b['vector']) ?: ($a['score']<=>$b['score']);});
  if($choice===null && $valid){$choice=$valid[0];}
 }
 return ['id'=>$id,'description'=>$descriptions[0]??'','assessment'=>$choice];
}
