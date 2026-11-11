<?php
defined('ABSPATH') || exit;
/** A separate opt-in CLI client. Never invoked on a page render or by Research collectors. */
class CDCA_Enrichment_Client {
 public $last_request=0;public $requests=0;
 public function policy($url) {
  cdca_need(cdca_public_url($url)!==null,'enrichment_url');$p=parse_url($url);$host=strtolower($p['host']);$path=$p['path']??'/';
  $allowed=['www.cisa.gov'=>['/sites/default/files/feeds/known_exploited_vulnerabilities.json'], 'export.arxiv.org'=>['/api/query']];
  cdca_need(isset($allowed[$host])&&(in_array($path,$allowed[$host],true)||($host==='www.cisa.gov'&&preg_match('~^/news-events/(?:alerts|cybersecurity-advisories|ics-advisories)/[a-zA-Z0-9/-]+$~D',$path))||$path==='/robots.txt'),'enrichment_access_not_permitted');
  if($path==='/api/query'){parse_str($p['query']??'',$q);cdca_need(array_keys($q)===['id_list']&&preg_match('/^\d{4}\.\d{4,5}(?:v\d+)?$/D',$q['id_list']),'enrichment_query');}
  else{cdca_need(empty($p['query']),'enrichment_query');}
  return ['host'=>$host,'license_or_usage_notes'=>$host==='export.arxiv.org'?'arXiv descriptive metadata (including abstracts): CC0 per API terms. E-print rights remain separate; article license not inferred.':'CISA catalog metadata excerpt; retain source attribution; no redistribution license inferred for linked third-party content.'];
 }
 public static function robots_allowed($body,$path) {
  cdca_need(strlen($body)<=262144,'robots_size');$groups=[];$agents=[];$rules=[];$started=false;
  $flush=static function()use(&$groups,&$agents,&$rules){if($agents){$groups[]=['agents'=>$agents,'rules'=>$rules];}$agents=[];$rules=[];};
  foreach(preg_split('/\r?\n/',$body) as $line){$line=trim(explode('#',$line,2)[0]);if(!str_contains($line,':')){continue;}[$key,$value]=array_map('trim',explode(':',$line,2));$key=strtolower($key);
   if($key==='user-agent'){if($started){$flush();$started=false;}$agents[]=strtolower($value);}
   elseif($agents&&in_array($key,['allow','disallow','crawl-delay'],true)){$rules[]=[$key,$value];$started=true;}
  }$flush();$chosen=[];$specific=false;
  foreach($groups as $g){$match=false;foreach($g['agents'] as $agent){if($agent!==''&&$agent!=='*'&&str_contains('cyberdat-evidence',$agent)){$match=true;}}
   if($match){if(!$specific){$chosen=[];}$specific=true;$chosen=array_merge($chosen,$g['rules']);}elseif(!$specific&&in_array('*',$g['agents'],true)){$chosen=array_merge($chosen,$g['rules']);}}
  $best=-1;$allow=true;foreach($chosen as [$kind,$value]){if($kind==='crawl-delay'){cdca_need(is_numeric($value)&&(float)$value<=5,'robots_crawl_delay');continue;}if($value===''){continue;}
   $pattern=preg_quote($value,'~');$pattern=str_replace('\\*','.*',$pattern);if(str_ends_with($value,'$')){$pattern=substr($pattern,0,-2).'$';}
   if(preg_match('~^'.$pattern.'~',$path)){$length=strlen(str_replace(['*','$'],'',$value));if($length>$best||($length===$best&&$kind==='allow')){$best=$length;$allow=$kind==='allow';}}
  }return $allow;
 }
 public function request($url,$limit=2097152,$redirects=0) {
  cdca_need(cdca_stage()&&defined('WP_CLI')&&WP_CLI&&PHP_SAPI==='cli','enrichment_cli_only');
  $policy=$this->policy($url);cdca_need($this->requests<6&&$redirects<=2,'enrichment_request_budget');
  $records=dns_get_record($policy['host'],DNS_A|DNS_AAAA);cdca_need(is_array($records)&&count($records)>0,'enrichment_dns');$ips=[];
  foreach($records as $r){$ip=$r['ip']??$r['ipv6']??null;if($ip!==null){cdca_need(cdra_public_ip($ip),'enrichment_ssrf');$ips[]=$ip;}}
  cdca_need(count($ips)>0,'enrichment_dns');usort($ips,static fn($a,$b)=>(int)str_contains($a,':')<=>(int)str_contains($b,':'));
  $pause=5-(microtime(true)-$this->last_request);if($pause>0){usleep((int)($pause*1000000));}$this->last_request=microtime(true);++$this->requests;
  $body='';$headers=[];$size=false;$header_bytes=0;$ch=curl_init($url);$ip=$ips[0];
  curl_setopt_array($ch,[CURLOPT_PROTOCOLS_STR=>'HTTPS',CURLOPT_REDIR_PROTOCOLS_STR=>'HTTPS',CURLOPT_FOLLOWLOCATION=>false,CURLOPT_MAXREDIRS=>0,CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,CURLOPT_PROXY=>'',CURLOPT_CONNECTTIMEOUT=>5,CURLOPT_TIMEOUT=>15,CURLOPT_RESOLVE=>[$policy['host'].':443:'.(str_contains($ip,':')?'['.$ip.']':$ip)],CURLOPT_USERAGENT=>'CyberDat-Evidence/0.9.0 (bounded staging metadata retrieval)',CURLOPT_HTTPHEADER=>['Accept: application/json, application/atom+xml, text/plain','Accept-Encoding: identity'],
   CURLOPT_WRITEFUNCTION=>static function($c,$chunk)use(&$body,&$size,$limit){if(strlen($body)+strlen($chunk)>$limit){$size=true;return 0;}$body.=$chunk;return strlen($chunk);},
   CURLOPT_HEADERFUNCTION=>static function($c,$line)use(&$headers,&$header_bytes){$header_bytes+=strlen($line);if($header_bytes>32768){return 0;}$parts=explode(':',$line,2);if(count($parts)===2){$k=strtolower(trim($parts[0]));if(in_array($k,['location','content-type','content-encoding','retry-after'],true)){$headers[$k]=trim($parts[1]);}}return strlen($line);}]);
  try{$ok=curl_exec($ch);$code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE);$errno=curl_errno($ch);}finally{curl_close($ch);}
  if($size){return ['status'=>'size_limit','http_status'=>$code,'retry_after'=>0];}
  if($ok===false){return ['status'=>$errno===CURLE_OPERATION_TIMEDOUT?'timeout':'transport','http_status'=>$code?:null,'retry_after'=>300,'curl_errno'=>$errno];}
  if(in_array($code,[301,302,303,307,308],true)){
   $next=$headers['location']??'';if(str_starts_with($next,'/')&&!str_starts_with($next,'//')){$next='https://'.$policy['host'].$next;}
   cdca_need((parse_url($next,PHP_URL_HOST)??'')===$policy['host'],'enrichment_redirect_host');$this->policy($next);return $this->request($next,$limit,$redirects+1);
  }
  $retry=$headers['retry-after']??'';$delay=ctype_digit($retry)?(int)$retry:max(0,(strtotime($retry)?:time())-time());
  if($code!==200){return ['status'=>in_array($code,[401,403,404,410],true)?'access_unavailable':'http_error','http_status'=>$code,'retry_after'=>min(86400,max($delay,$code===429||$code>=500?300:0))];}
  cdca_need(!isset($headers['content-encoding'])||in_array(strtolower($headers['content-encoding']),['','identity'],true),'enrichment_encoding');
  return ['status'=>'ok','http_status'=>200,'body'=>$body,'content_type'=>strtolower(explode(';',$headers['content-type']??'')[0]),'url'=>$url,'license_or_usage_notes'=>$policy['license_or_usage_notes'],'retry_after'=>0];
 }
 public function fetch($url) {
  $policy=$this->policy($url);$robot=$this->request('https://'.$policy['host'].'/robots.txt',262144);
  // Missing/unavailable robots does not become implicit permission in this implementation.
  if($robot['status']!=='ok'){return ['status'=>'robots_unavailable','http_status'=>$robot['http_status'],'retry_after'=>$robot['retry_after']??0];}
  if(!self::robots_allowed($robot['body'],(parse_url($url,PHP_URL_PATH)??'/').(parse_url($url,PHP_URL_QUERY)?'?'.parse_url($url,PHP_URL_QUERY):''))){return ['status'=>'robots_denied','http_status'=>null,'retry_after'=>0];}
  return $this->request($url);
 }
 public function extract($response,$source) {
  cdca_need($response['status']==='ok','enrichment_response');$body=$response['body'];$text=null;$locator=null;$method=null;$kind='source_claim';
  if($source['source']==='arxiv'){
   cdca_need(in_array($response['content_type'],['application/atom+xml','application/xml','text/xml'],true)&&!preg_match('/<!DOCTYPE|<!ENTITY/i',$body),'enrichment_xml');
   $old=libxml_use_internal_errors(true);try{$xml=simplexml_load_string($body,SimpleXMLElement::class,LIBXML_NONET);cdca_need($xml!==false,'enrichment_xml');$a=$xml->children('http://www.w3.org/2005/Atom');$entry=$a->entry[0]??null;cdca_need($entry!==null,'enrichment_not_found');$actual=(string)$entry->id;$expected=$source['paper']['arxiv_id']??'';cdca_need(preg_match('~/(\d{4}\.\d{4,5})(?:v\d+)?$~',$actual,$m)&&$m[1]===preg_replace('/v\d+$/','',$expected),'enrichment_identity');$text=trim((string)$entry->summary);$locator='Atom entry/summary';$method='arxiv_api_abstract';}finally{libxml_clear_errors();libxml_use_internal_errors($old);}
  }elseif($source['source']==='cisa-advisories'){
   cdca_need($response['content_type']==='text/html'&&!preg_match('/captcha|access denied|verify you are human/i',$body),'enrichment_html');
   $old=libxml_use_internal_errors(true);try{$dom=new DOMDocument();$dom->loadHTML($body,LIBXML_NONET|LIBXML_NOERROR|LIBXML_NOWARNING);$xp=new DOMXPath($dom);$article=$xp->query('//article')->item(0)??$xp->query('//main')->item(0);cdca_need($article!==null,'enrichment_article_missing');foreach($xp->query('.//script|.//style|.//nav|.//form|.//noscript',$article) as $node){$node->parentNode->removeChild($node);}$text=trim($article->textContent);cdca_need(mb_strlen($text)>=100,'enrichment_empty');$locator='HTML article/main (bounded excerpt; may include page chrome; completeness unproven)';$method='cisa_article_text_excerpt';}finally{libxml_clear_errors();libxml_use_internal_errors($old);}
  }elseif($source['source']==='kev'){
   cdca_need(in_array($response['content_type'],['application/json','text/plain'],true),'enrichment_json');$doc=json_decode($body,true,64,JSON_THROW_ON_ERROR);
   foreach($doc['vulnerabilities']??[] as $v){if(in_array($v['cveID']??'', $source['cves'],true)){$text=cdca_json(array_intersect_key($v,array_flip(['cveID','shortDescription','requiredAction','dueDate','dateAdded','knownRansomwareCampaignUse'])));$locator='KEV vulnerabilities[cveID='.$v['cveID'].']';break;}}
   cdca_need($text!==null,'enrichment_not_found');$method='cisa_catalog_record';$kind='cve_metadata';
  }else{throw new CDCA_Error('enrichment_access_not_permitted');}
  cdca_need(is_string($text)&&trim($text)!=='','enrichment_empty');$truncated=mb_strlen($text)>12000;$text=cdca_evidence_text($text,12000);
  return ['level'=>$source['source']==='arxiv'?'abstract':'summary','content_available'=>true,'content_truncated'=>$truncated,'content_source_url'=>$response['url'],'content_fetched_at'=>gmdate('c'),'content_hash'=>hash('sha256',$text),'extraction_method'=>$method,'extraction_status'=>'available','license_or_usage_notes'=>$response['license_or_usage_notes'],'limitations'=>['No full-paper/article extraction or republication permission asserted.'],'text'=>$text,'locator'=>$locator,'evidence_type'=>$kind];
 }
}
