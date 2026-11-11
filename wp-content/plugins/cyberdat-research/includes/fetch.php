<?php
defined('ABSPATH') || exit;
function cdra_public_ip($ip){
 if(!filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_NO_PRIV_RANGE|FILTER_FLAG_NO_RES_RANGE)){return false;}
 if(str_contains($ip,':')){return preg_match('/^[23][0-9a-f]{3}:/i',$ip)&&!preg_match('/^(?:2002:|2001:0:|2001:db8:)/i',$ip);}
 $n=(int)sprintf('%u',ip2long($ip));
 foreach([['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],['172.16.0.0',12],['192.0.0.0',24],['192.0.2.0',24],['192.168.0.0',16],['198.18.0.0',15],['198.51.100.0',24],['203.0.113.0',24],['224.0.0.0',4],['240.0.0.0',4]] as [$network,$bits]){$mask=(0xffffffff << (32-$bits))&0xffffffff;if(($n&$mask)===(ip2long($network)&$mask)){return false;}}
 return true;
}
function cdra_query($source,$query){
 if(isset(cdra_discovery_registry()[$source])){return cdra_discovery_query($source,$query);}
 cdra_need(isset(cdra_sources()[$source]),'source_not_allowed');
 if($source!=='nvd'){cdra_need(!$query,'query_rejected');return '';}
 cdra_need(!array_diff(array_keys($query),['cveIds','lastModStartDate','lastModEndDate','resultsPerPage','startIndex']),'query_rejected');
 cdra_need(isset($query['resultsPerPage'],$query['startIndex'])&&is_int($query['resultsPerPage'])&&$query['resultsPerPage']>=1&&$query['resultsPerPage']<=200&&is_int($query['startIndex'])&&$query['startIndex']>=0,'query_pagination');
 if(isset($query['cveIds'])){cdra_need(!isset($query['lastModStartDate'],$query['lastModEndDate'])&&preg_match('/^CVE-\d{4}-\d{4,19}(?:,CVE-\d{4}-\d{4,19}){0,2}$/D',$query['cveIds']),'query_cve_ids');}
 else{cdra_need(isset($query['lastModStartDate'],$query['lastModEndDate']),'query_window');$start=cdra_time($query['lastModStartDate']);$end=cdra_time($query['lastModEndDate']);cdra_need($end>=$start&&$end-$start<=86400&&$end<=time()+300,'query_window');}
 return '?'.http_build_query($query,'','&',PHP_QUERY_RFC3986);
}
class CDRA_Client {
 public function get($source,$query=[],$validators=[]){
  cdra_need(cdra_staging()&&defined('WP_CLI')&&WP_CLI&&PHP_SAPI==='cli','cli_staging_only');
  $permission='/etc/cyberdat-staging/research.json';cdra_need(is_readable($permission)&&!is_link($permission)&&fileowner($permission)===0,'owner_permission_required');$grant=json_decode(file_get_contents($permission),true);cdra_need($grant===['enabled'=>true,'host'=>'staging.cyberdat.eu'],'owner_permission_required');
  $suffix=cdra_query($source,$query);$spec=cdra_spec($source);$p=wp_parse_url($spec['url']);$host=$p['host'];
  $records=dns_get_record($host,DNS_A|DNS_AAAA);cdra_need(is_array($records),'dns_failed');$ips=[];
  foreach($records as $row){$ip=$row['ip']??($row['ipv6']??null);if($ip!==null){cdra_need(cdra_public_ip($ip),'ssrf_address');$ips[]=$ip;}}
  cdra_need(count($ips)>0,'dns_failed');usort($ips,static fn($a,$b)=>(int)str_contains($a,':')<=>(int)str_contains($b,':'));$ip=$ips[0];
  $headers=['Accept: '.(in_array($spec['format'],['rss','arxiv'],true)?'application/rss+xml, application/atom+xml, application/xml, text/xml':'application/json'),'Accept-Encoding: identity'];
  foreach(['etag'=>'If-None-Match','last_modified'=>'If-Modified-Since'] as $key=>$name){if(isset($validators[$key])&&is_string($validators[$key])&&strlen($validators[$key])<=512&&!preg_match('/[\r\n\x00]/',$validators[$key])){$headers[]=$name.': '.$validators[$key];}}
  if($source==='nvd'&&is_readable('/etc/cyberdat-staging/nvd-api.key')){$key=trim(file_get_contents('/etc/cyberdat-staging/nvd-api.key'));cdra_need(preg_match('/^[A-Za-z0-9-]{1,256}$/D',$key),'invalid_api_key');$headers[]='apiKey: '.$key;}
  $body='';$response_headers=[];$bytes=0;$overflow=false;$bounded_prefix=false;$bounded_records=0;$limit=in_array($spec['format'],['rss','arxiv'],true)?2097152:4194304;
  $curl=curl_init($spec['url'].$suffix);cdra_need($curl!==false,'curl_init');
  $protocols=defined('CURLOPT_PROTOCOLS_STR')?[CURLOPT_PROTOCOLS_STR=>'HTTPS',CURLOPT_REDIR_PROTOCOLS_STR=>'HTTPS']:[CURLOPT_PROTOCOLS=>CURLPROTO_HTTPS,CURLOPT_REDIR_PROTOCOLS=>CURLPROTO_HTTPS];
  curl_setopt_array($curl,$protocols+[CURLOPT_HTTPGET=>true,CURLOPT_FOLLOWLOCATION=>false,CURLOPT_MAXREDIRS=>0,CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,CURLOPT_PROXY=>'',CURLOPT_CONNECTTIMEOUT=>5,CURLOPT_TIMEOUT=>12,CURLOPT_HTTPHEADER=>$headers,CURLOPT_USERAGENT=>'CyberDat-Research/0.8.1 (staging official-source ingestion)',CURLOPT_RESOLVE=>[$host.':443:'.(str_contains($ip,':')?'['.$ip.']':$ip)],CURLOPT_WRITEFUNCTION=>static function($handle,$chunk)use(&$body,&$overflow,&$bounded_prefix,&$bounded_records,$limit,$spec){if(strlen($body)+strlen($chunk)>$limit){if($spec['format']==='rss'){$count=preg_match_all('~</(?:[A-Za-z_][\w.-]*:)?(?:item|entry)\s*>~i',$body);if($count>0){$prefix=cdra_feed_prefix($body,min(25,$count));if($prefix!==null){$body=$prefix;$bounded_prefix=true;$bounded_records=min(25,$count);return 0;}}}$overflow=true;return 0;}$body.=$chunk;if($spec['format']==='rss'&&preg_match_all('~</(?:[A-Za-z_][\w.-]*:)?(?:item|entry)\s*>~i',$body)>=25){$prefix=cdra_feed_prefix($body);if($prefix!==null){$body=$prefix;$bounded_prefix=true;$bounded_records=25;return 0;}}return strlen($chunk);},CURLOPT_HEADERFUNCTION=>static function($handle,$line)use(&$response_headers,&$bytes){$bytes+=strlen($line);if($bytes>65536){return 0;}$parts=explode(':',$line,2);if(count($parts)===2){$key=strtolower(trim($parts[0]));if(in_array($key,['etag','last-modified','retry-after','content-type','content-encoding'],true)){$response_headers[$key]=trim($parts[1]);}}return strlen($line);}]);
  try{$ok=curl_exec($curl);$status=(int)curl_getinfo($curl,CURLINFO_HTTP_CODE);$errno=curl_errno($curl);$types=[6=>'dns',7=>'connect',28=>'timeout',35=>'tls',51=>'tls_verify',52=>'empty_reply',56=>'receive',60=>'tls_verify',92=>'http2_stream'];$diag=['kind'=>$types[$errno]??($errno?'curl_transport':'http'),'curl_errno'=>$errno,'http_status'=>$status?:null,'connect_ms'=>(int)round(curl_getinfo($curl,CURLINFO_CONNECT_TIME)*1000),'tls_ms'=>(int)round(curl_getinfo($curl,CURLINFO_APPCONNECT_TIME)*1000),'total_ms'=>(int)round(curl_getinfo($curl,CURLINFO_TOTAL_TIME)*1000)];if($overflow){throw new CDRA_Error('response_size',0,$diag);}if($ok===false&&!$bounded_prefix){throw new CDRA_Error('transport',0,$diag);}}

  finally{curl_close($curl);}
  if(!in_array($status,[200,304],true)){$header=$response_headers['retry-after']??'';$retry=ctype_digit($header)?(int)$header:max(0,(strtotime($header)?:time())-time());throw new CDRA_Error('http_'.$status,$retry,$diag);}
  cdra_need(!isset($response_headers['content-encoding'])||in_array(strtolower($response_headers['content-encoding']),['identity',''],true),'content_encoding');
  if($status===200){$type=strtolower(trim(explode(';',$response_headers['content-type']??'')[0]));cdra_need(in_array($type,in_array($spec['format'],['rss','arxiv'],true)?['application/rss+xml','application/atom+xml','application/xml','text/xml']:['application/json','text/plain'],true),'content_type');}
  if($bounded_prefix){$diag['kind']='intentional_bounded_feed';}
  return ['status'=>$status,'body'=>$body,'headers'=>$response_headers,'bounded_feed_prefix'=>$bounded_prefix,'bounded_feed_records'=>$bounded_records,'diagnostic'=>$diag];
 }
}
