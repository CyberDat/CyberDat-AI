<?php
/** Discovery extension: same Research Agent, store, secure client and ingestion lock. */
defined('ABSPATH') || exit;
function cdra_discovery_registry(){static $registry;return $registry??=json_decode(file_get_contents(__DIR__.'/discovery-sources.json'),true,32,JSON_THROW_ON_ERROR);}
function cdra_spec($source){
 if(isset(cdra_sources()[$source])){return cdra_sources()[$source];}
 $r=cdra_discovery_registry()[$source]??null;cdra_need(is_array($r)&&!empty($r['url']),'source_not_allowed');
 $host=wp_parse_url($r['url'],PHP_URL_HOST);$site=wp_parse_url($r['website'],PHP_URL_HOST);
 return $r+['fresh'=>$r['interval']*3,'hosts'=>array_values(array_unique([$host,$site]))];
}
function cdra_discovery_enabled($source,$store){$r=cdra_discovery_registry()[$source]??null;return $r&&$r['connection']!=='BLOCKED'&&$store->get('discovery_enabled:'.$source,false)===true;}
function cdra_discovery_categories(){return ['Cybersecurity News','Vulnerabilities','Threat Intelligence','Malware','Ransomware','AI Security','LLM & Agent Security','Cloud Security','Network Security','Privacy','Incident Response','Reverse Engineering','Scientific Research','IoT / ICS / OT','Digital Forensics','Exploit Mitigations','Cryptography & Privacy'];}
function cdra_discovery_classify($title,$summary,$stream){
 $text=mb_strtolower($title.' '.$summary);$rules=[
 'Vulnerabilities'=>['cve-','vulnerability','vulnerabilities','exploit'], 'Malware'=>['malware','trojan','backdoor'], 'Ransomware'=>['ransomware'],
 'AI Security'=>['artificial intelligence','machine learning','language model','llm'], 'LLM & Agent Security'=>['prompt injection','agent security','language model','llm'],
 'Cloud Security'=>['cloud','kubernetes','container','docker'], 'Network Security'=>['network','firewall','router'], 'Privacy'=>['privacy','anonymization'],
 'Incident Response'=>['incident response','data breach','forensic'], 'Reverse Engineering'=>['reverse engineering','decompil'],
 'IoT / ICS / OT'=>['modbus','industrial control','iot','scada','bacnet'], 'Digital Forensics'=>['forensic'],
 'Exploit Mitigations'=>['mitigation','memory safety','control-flow'], 'Cryptography & Privacy'=>['cryptograph','encryption','privacy']];
 $categories=[$stream==='news'?'Cybersecurity News':($stream==='papers'?'Scientific Research':'Threat Intelligence')];$reasons=[['category'=>$categories[0],'basis'=>'Registry content stream']];
 foreach($rules as $category=>$terms){foreach($terms as $term){if(str_contains($text,$term)){$categories[]=$category;$reasons[]=['category'=>$category,'basis'=>'Keyword: '.$term];break;}}}
 return ['categories'=>array_values(array_unique($categories)),'reasons'=>$reasons,'method'=>'deterministic-v1'];
}
function cdra_discovery_url($url){$url=cdra_url($url);$p=wp_parse_url($url);$q=[];parse_str($p['query']??'',$q);foreach(array_keys($q) as $k){if(preg_match('/^(?:utm_|mc_|pk_)/i',$k)||in_array(strtolower($k),['fbclid','gclid','ref','ref_src'],true)){unset($q[$k]);}}ksort($q);return 'https://'.strtolower($p['host']).($p['path']??'/').($q?'?'.http_build_query($q,'','&',PHP_QUERY_RFC3986):'');}
function cdra_discovery_timestamp($value){cdra_need(is_string($value)&&strlen($value)<=128,'discovery_date');$at=strtotime($value);cdra_need($at!==false&&$at<=time()+300&&$at>=strtotime('1990-01-01 UTC'),'discovery_date');return gmdate('Y-m-d\TH:i:s\Z',$at);}
function cdra_discovery_doi($value){$value=strtolower(trim(preg_replace('~^https?://(?:dx\.)?doi\.org/~i','',(string)$value)));cdra_need(strlen($value)<=256&&preg_match('~^10\.\d{4,9}/[^\s<>]+$~uD',$value),'paper_doi');return $value;}
function cdra_discovery_record($source,$id,$url,$title,$summary,$published,$updated=null,$extra=[]){
 $spec=cdra_spec($source);$title=trim(html_entity_decode(wp_strip_all_tags($title),ENT_QUOTES,'UTF-8'));$summary=trim(html_entity_decode(wp_strip_all_tags($summary),ENT_QUOTES,'UTF-8'));
 cdra_need($title!==''&&strlen($title)<=2048,'discovery_title');$url=cdra_discovery_url($url);$published=cdra_discovery_timestamp($published);$updated=$updated?cdra_discovery_timestamp($updated):$published;
 preg_match_all('/\bCVE-\d{4}-\d{4,19}\b/i',$title.' '.$summary,$ids);$cves=array_values(array_unique(array_map('strtoupper',$ids[0])));sort($cves);
 $class=cdra_discovery_classify($title,$summary,$spec['stream']);
 $record=array_merge(['source'=>$source,'source_name'=>$spec['name'],'source_id'=>cdra_text($id,2048),'canonical_url'=>$url,'original_url'=>$url,'publisher'=>$spec['publisher'],
 'original_title'=>$title,'summary'=>mb_substr($summary,0,2000),'published'=>$published,'source_updated'=>$updated,'source_timezone'=>null,'cve_ids'=>$cves,'assessment'=>null,'assessments'=>[],'cwe'=>[],
 'references'=>[$url],'vendor'=>null,'product'=>null,'kev_confirmed'=>false,'source_url'=>$spec['url'],'stream'=>$spec['stream'],'content_type'=>$spec['stream']==='papers'?'Cybersecurity Research Papers':$spec['stream'],
 'authors'=>[],'categories'=>$class['categories'],'classification_reasons'=>$class['reasons'],'tags'=>[],'technologies'=>[],'paper'=>null],$extra);
 if($record['paper']){$map=['AI Security'=>'AI & LLM Security','LLM & Agent Security'=>'Prompt Injection & Agent Security','Malware'=>'Malware Analysis','Reverse Engineering'=>'Reverse Engineering','Vulnerabilities'=>'Vulnerability Research','Exploit Mitigations'=>'Exploit Mitigations','Network Security'=>'Network Security','Cloud Security'=>'Cloud & Container Security','IoT / ICS / OT'=>'IoT / ICS / OT Security','Cryptography & Privacy'=>'Cryptography & Privacy','Privacy'=>'Cryptography & Privacy','Digital Forensics'=>'Digital Forensics'];$categories=[];foreach($record['categories'] as $cat){if(isset($map[$cat])){$categories[]=$map[$cat];}}$record['paper']['research_categories']=array_values(array_unique($categories));}
 return $record;
}
function cdra_discovery_xml($body){
 cdra_need(strlen($body)<=2097152&&!preg_match('/<!\s*(?:DOCTYPE|ENTITY)/i',$body),'xml_entities_rejected');$old=libxml_use_internal_errors(true);
 try{$xml=simplexml_load_string($body,'SimpleXMLElement',LIBXML_NONET|LIBXML_NOCDATA);cdra_need($xml!==false,'xml_parse');return $xml;}finally{libxml_clear_errors();libxml_use_internal_errors($old);}
}
function cdra_discovery_parse($source,$body){
 $spec=cdra_spec($source);$out=[];
 if($spec['format']==='crossref'){
  $data=json_decode($body,true,64,JSON_THROW_ON_ERROR);cdra_need(($data['status']??'')==='ok'&&is_array($data['message']['items']??null),'crossref_schema');
  foreach(array_slice($data['message']['items'],0,25) as $row){
   $doi=cdra_discovery_doi($row['DOI']??'');$parts=$row['published']['date-parts'][0]??null;if(!is_array($parts)||count($parts)<3){continue;}
   $date=sprintf('%04d-%02d-%02dT00:00:00Z',...array_slice($parts,0,3));$authors=[];foreach(array_slice($row['author']??[],0,100) as $a){$authors[]=trim(($a['given']??'').' '.($a['family']??''));}
   $out[]=cdra_discovery_record($source,$doi,'https://doi.org/'.$doi,$row['title'][0]??'','',$date,$row['deposited']['date-time']??$date,['authors'=>$authors,'paper'=>['doi'=>$doi,'arxiv_id'=>null,'openalex_id'=>null,'semantic_scholar_id'=>null,'venue'=>$row['container-title'][0]??null,'publisher'=>$row['publisher']??null,'review_status'=>'Unknown','abstract'=>null,'open_access_url'=>null,'code_url'=>null,'revision'=>null],'source_timezone'=>'UTC date precision']);
  }
 }else{
  $xml=cdra_discovery_xml($body);$entries=$xml->xpath('//*[local-name()="item" or local-name()="entry"]');cdra_need(is_array($entries),'feed_schema');
  foreach(array_slice($entries,0,25) as $entry){
   $entry->registerXPathNamespace('a','http://www.w3.org/2005/Atom');$entry->registerXPathNamespace('x','http://arxiv.org/schemas/atom');
   $get=static function($name)use($entry){$v=$entry->xpath('./*[local-name()="'.$name.'"]');return $v?(string)$v[0]:'';};
   $url='';foreach($entry->xpath('./*[local-name()="link"]') as $link){if((string)$link['href']!==''&&in_array((string)$link['rel'],['','alternate'],true)){$url=(string)$link['href'];break;}if(trim((string)$link)!==''){$url=trim((string)$link);}}
   $id=$get('guid')?:$get('id')?:$url;$date=$get('pubDate')?:$get('published');if($date===''){continue;} // Missing publication is unknown, not ingestion time.
   $updated=$get('updated')?:$date;$extra=['source_timezone'=>$date,'authors'=>[]];foreach($entry->xpath('./*[local-name()="author"]') as $author){$n=$author->xpath('./*[local-name()="name"]');$extra['authors'][]=trim($n?(string)$n[0]:(string)$author);}
   if($spec['format']==='arxiv'){
    cdra_need(preg_match('~(?:arxiv\.org/abs/)(\d{4}\.\d{4,5}|[a-z.-]+/\d{7})(v\d+)?$~i',$id,$m),'arxiv_id');$id=$m[1];$url='https://arxiv.org/abs/'.$id;
    $doi=$get('doi');$extra['paper']=['doi'=>$doi?cdra_discovery_doi($doi):null,'arxiv_id'=>$id,'openalex_id'=>null,'semantic_scholar_id'=>null,'venue'=>$get('journal_ref')?:null,'publisher'=>'arXiv','review_status'=>'Preprint','abstract'=>mb_substr(wp_strip_all_tags($get('summary')),0,12000),'open_access_url'=>$url,'code_url'=>null,'revision'=>$m[2]??null];
   }else{cdra_url($url,$spec['hosts']);}
   $out[]=cdra_discovery_record($source,$id,$url,$get('title'),$get('description')?:$get('summary'),$date,$updated,$extra);
  }
 }
 cdra_need(count($out)>0||in_array($spec['format'],['crossref','arxiv'],true),'discovery_empty');return $out;
}
function cdra_discovery_priority($r,$kev,$changed=false,$now=null){
 $now=$now??time();$reasons=[];$add=static function($factor,$points,$explanation)use(&$reasons){$reasons[]=['factor'=>$factor,'points'=>$points,'explanation'=>$explanation];};
 $add('source',(int)round(cdra_spec($r['source'])['priority']/5),'Registry source reliability weight; reputation is not proof of each claim.');
 $age=max(0,$now-cdra_time($r['published']));$add('recency',$age<=86400?15:($age<=604800?8:0),'Source publication date, not discovery date.');
 if($kev){$add('exploitation',30,'Related CVE confirmed in current CISA KEV; not a probability or proof this story is a new attack.');}
 $a=$r['assessment']??null;if($a){$add('severity',min(20,(int)round($a['score']*2)),'Confirmed source CVSS '.$a['version']);}
 $add('relevance',min(15,count($r['categories'])*3),'Deterministic category matches, not LLM assessment.');
 if($changed){$add('update',5,'Material source update; not scientific novelty.');}
 if($r['paper']){if($r['paper']['review_status']==='Peer-reviewed'){$add('peer_review',5,'Verified venue review metadata.');}if($r['paper']['code_url']){$add('reproducibility',5,'Source supplies supporting code; reproducibility not independently verified.');}$add('research',5,'Cybersecurity research relevance; novelty and validity require human review.');}
 if(preg_match('/\b(?:mitigation|remediation|detection|patch|defen[cs]e)\b/i',$r['original_title'].' '.$r['summary'])){$add('defensive_value',5,'Source metadata mentions a practical defensive topic; content is not independently validated.');}
 $add('novelty',0,'Scientific novelty and independence of corroboration require editorial verification; syndicated copies receive no corroboration bonus.');
 $score=min(100,array_sum(array_column($reasons,'points')));return ['score'=>$score,'level'=>$score>=80?'High':($score>=50?'Medium':'Low'),'reasons'=>$reasons,'kind'=>'editorial_heuristic_not_EPSS'];
}
