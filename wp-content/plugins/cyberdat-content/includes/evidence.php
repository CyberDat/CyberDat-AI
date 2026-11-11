<?php
/** Versioned, untrusted evidence. Completeness and semantic truth are separate properties. */
defined('ABSPATH') || exit;
function cdca_public_url($url) {
 if (!is_string($url) || strlen($url)>2048 || preg_match('/[\x00-\x20\\\\]/',$url)) { return null; }
 $p=parse_url($url); if (!$p || ($p['scheme']??'')!=='https' || isset($p['user'],$p['pass']) || isset($p['user']) || isset($p['pass']) || (isset($p['port']) && $p['port']!==443)) { return null; }
 $host=strtolower($p['host']??'');
 if (!preg_match('/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/D',$host) || preg_match('/\.(?:local|internal|localhost|test|invalid|lan|home|arpa)$/D',$host)) { return null; }
 if (preg_match('/(?:token|secret|password|api[_-]?key|auth|signature|session|cookie)=/i',$p['query']??'')) { return null; }
 return $url;
}
function cdca_evidence_text($value,$limit=12000) {
 if ($value===null) { return null; }
 cdca_need(is_string($value),'evidence_text');
 $value=html_entity_decode(strip_tags($value),ENT_QUOTES|ENT_HTML5,'UTF-8');
 $value=preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/u','',$value);
 $value=preg_replace('/\b(?:Bearer\s+[a-zA-Z0-9._-]{12,}|(?:password|api[_-]?key|secret|access[_-]?token|cookie|session|authorization)\s*[:=]\s*[^\s,;]{6,})/i','[credential-like text redacted]',$value);
 $value=preg_replace_callback('~https?://[^\s<>"\x27]+~i',static fn($m)=>cdca_public_url($m[0])??'[non-public or sensitive URL omitted]',$value);
 $value=preg_replace('/\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|127\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})\b/','[private address omitted]',$value);
 $value=preg_replace('/(?<![0-9a-f:])(?:f[cd][0-9a-f]{2}|fe[89ab][0-9a-f]):[0-9a-f:]+|(?<![0-9a-f:])::1(?![0-9a-f:])/i','[private address omitted]',$value);
 return mb_substr($value,0,$limit);
}
function cdca_evidence_data($v,$depth=0) {
 cdca_need($depth<=12,'evidence_depth');
 if (is_string($v)) { return cdca_evidence_text($v); }
 if (!is_array($v)) { return is_scalar($v)||$v===null?$v:null; }
 $out=[]; foreach(array_slice($v,0,100,true) as $k=>$value) {
  if (is_string($k) && preg_match('/password|secret|cookie|token|authorization|api_key/i',$k)) { continue; }
  $out[$k]=cdca_evidence_data($value,$depth+1);
 } return $out;
}
function cdca_source_record($row,$n) {
 $v=json_decode($row['payload'],true,64,JSON_THROW_ON_ERROR);$meta=isset($row['metadata'])?json_decode($row['metadata'],true,64,JSON_THROW_ON_ERROR):[];
 $url=cdca_public_url($row['canonical_url']??$v['canonical_url']??null);cdca_need($url!==null,'research_source_url');
 $summary=array_key_exists('summary',$v)?cdca_evidence_text($v['summary']):null;
 $paper=$meta['paper']??$v['paper']??null;$paper=$paper===null?null:cdca_evidence_data($paper);
 $abstract=is_array($paper)?($paper['abstract']??null):null;
 $text=is_string($abstract)&&trim($abstract)!==''?$abstract:($summary??'');
 $level=$text===''?'metadata_only':(is_string($abstract)&&trim($abstract)!==''?'abstract':'summary');
 // The legacy payload did not persist clipping flags. Boundary-sized summaries are suspect;
 // otherwise truncation remains unknown, never asserted false from a short string alone.
 $length=mb_strlen($v['summary']??'');$clipped=in_array($length,[2000,8000,12000],true)?true:null;
 $source=['id'=>'S'.$n,'research_item_id'=>(int)$row['id'],'source_id'=>cdca_evidence_text($row['source_id']??$v['source_id']??'',2048),'source'=>$row['source']??$v['source'],
  'topic_id'=>$row['topic_id']??null,'content_hash'=>$row['content_hash'],'canonical_url'=>$url,'url'=>$url,'original_url'=>cdca_public_url($v['original_url']??null),
  'publisher'=>cdca_evidence_text($v['publisher']??$v['source_name']??$v['source']??null,500),'authors'=>array_key_exists('authors',$meta)?cdca_evidence_data($meta['authors']):(array_key_exists('authors',$v)?cdca_evidence_data($v['authors']):null),
  'published'=>$v['published']??null,'source_updated'=>$v['source_updated']??null,'publication_precision'=>$v['source_timestamp_basis']??null,
  'first_seen'=>$row['first_seen']??null,'last_seen'=>$row['last_seen']??null,'title'=>cdca_evidence_text($v['original_title']??null,500),'summary'=>$summary,'abstract'=>$abstract,'paper'=>$paper,
  'categories'=>$meta['manual_categories']??$v['categories']??null,'priority'=>isset($row['manual_priority'])?(int)$row['manual_priority']:(isset($row['priority'])?(int)$row['priority']:null),
  'priority_reasons'=>isset($row['reasons'])?json_decode($row['reasons'],true):null,'content_type'=>$v['content_type']??null,'stream'=>$row['stream']??$v['stream']??null,'cves'=>$v['cve_ids']??[],
  'cwe'=>$v['cwe']??null,'cvss'=>$v['assessment']??null,'cvss_assessments'=>$v['assessments']??null,'severity'=>$row['severity']??null,
  'active'=>isset($row['active'])?(bool)$row['active']:null,'kev_confirmed'=>isset($row['kev_confirmed'])?((bool)$row['kev_confirmed']&&(($row['source']??'')!=='kev'||(bool)($row['active']??false))):($v['kev_confirmed']??null),
  'references'=>array_values(array_filter(array_map('cdca_public_url',$v['references']??[]))),
  'content'=>['level'=>$level,'content_available'=>$text!=='','content_truncated'=>$clipped,'content_source_url'=>$url,'content_fetched_at'=>$row['last_seen']??null,'content_hash'=>hash('sha256',$text),'extraction_method'=>'research_feed_projection','extraction_status'=>$text===''?'no_content':'available','license_or_usage_notes'=>null,'limitations'=>['Collector summary/abstract; full article completeness not established.','Historical truncation and original receipt time are not fully recorded.']],
  'provenance'=>['storage'=>'cdra_items.payload + cdra_discovery.metadata','research_item_id'=>(int)$row['id'],'research_content_hash'=>$row['content_hash'],'fields'=>[]]];
 $origins=['id'=>'derived per-brief source ordinal','research_item_id'=>'items.id','source_id'=>'items.source_id','source'=>'items.source','topic_id'=>'discovery.topic_id','canonical_url'=>'items.canonical_url','url'=>'items.canonical_url','title'=>'payload.original_title','authors'=>array_key_exists('authors',$meta)?'discovery.metadata.authors':'payload.authors','paper'=>isset($meta['paper'])?'discovery.metadata.paper':'payload.paper','abstract'=>isset($meta['paper'])?'discovery.metadata.paper.abstract':'payload.paper.abstract','categories'=>isset($meta['manual_categories'])?'discovery.metadata.manual_categories':'payload.categories','priority'=>isset($row['manual_priority'])?'items.manual_priority':'items.priority','priority_reasons'=>'items.reasons','content_type'=>'payload.content_type','stream'=>'discovery.stream/payload.stream','cves'=>'payload.cve_ids','cwe'=>'payload.cwe','cvss'=>'payload.assessment','cvss_assessments'=>'payload.assessments','kev_confirmed'=>'items.kev_confirmed','references'=>'payload.references','publication_precision'=>'payload.source_timestamp_basis','content'=>'derived availability from payload.summary/paper.abstract; no full-text assumption'];
 foreach(array_keys($source) as $field) {if($field!=='provenance'){$source['provenance']['fields'][$field]=['origin'=>$origins[$field]??(array_key_exists($field,$row)?'items.'.$field:'payload.'.$field),'source_hash'=>$row['content_hash'],'transformation'=>'Text stripped/bounded; non-public URLs and credential-like strings omitted.'];}}
 return cdca_evidence_data($source);
}
function cdca_fragments($sources) {
 $out=[];
 foreach($sources as $s) {
  foreach(['summary','abstract'] as $field) {
   $text=$s[$field]??null;if(!is_string($text)||trim($text)===''||($field==='abstract'&&$text===($s['summary']??null))){continue;}
   $out[]=['id'=>'E'.substr(cdca_hash([$s['research_item_id'],$s['content_hash'],$field,$text]),0,32),'research_item_id'=>$s['research_item_id'],'source_id'=>$s['id'],'source'=>$s['source'],'url'=>$s['url'],'source_type'=>$s['stream']??'research_metadata','published'=>$s['published'],'received_at'=>$s['last_seen'],'text'=>$text,'locator'=>'research.payload.'.$field,'context'=>$s['title'],'evidence_type'=>'source_claim','verification_status'=>'unverified','source_version_hash'=>$s['content_hash'],'limitations'=>['Automatically extracted source claim; not independently verified.']];
  }
  if(count($s['cves']??[])>0){$out[]=['id'=>'E'.substr(cdca_hash([$s['research_item_id'],$s['content_hash'],'cve']),0,32),'research_item_id'=>$s['research_item_id'],'source_id'=>$s['id'],'source'=>$s['source'],'url'=>$s['url'],'source_type'=>'vulnerability_metadata','published'=>$s['published'],'received_at'=>$s['last_seen'],'text'=>cdca_json(['cves'=>$s['cves'],'cwe'=>$s['cwe'],'cvss'=>$s['cvss'],'kev_confirmed'=>$s['kev_confirmed']]),'locator'=>'research.payload.cve_ids/assessment','context'=>$s['title'],'evidence_type'=>'cve_metadata','verification_status'=>'source_reported','source_version_hash'=>$s['content_hash'],'limitations'=>['Registry attribution does not verify exploitation or every narrative claim.']];}
 } return $out;
}
/** Gate is scoped to a template/depth. Two URLs are never counted as corroboration. */
function cdca_sufficiency($e,$template) {
 $missing=[];$sources=$e['sources']??[];$fragments=$e['fragments']??[];$official=false;$dated=false;$technical=false;$full=false;$has_cve=false;
 $official_sources=['kev','nvd','msrc','cisa-advisories','cert-eu','cisco-advisories','bsi','ncsc','ms-security','google-security','project-zero','owasp-genai'];
 foreach($sources as $s) {
  $has_text=mb_strlen($s['summary']??$s['abstract']??'')>=100;
  if(in_array($s['source']??'', $official_sources,true)&&$has_text&&!empty($s['published'])&&cdca_public_url($s['url']??null)){$official=true;}
  if(!empty($s['published'])&&!empty($s['title'])&&$has_text){$dated=true;}
  if(($s['content']['level']??'')==='full_text'&&($s['content']['content_truncated']??null)===false){$full=true;}
  if(count($s['cves']??[])&&in_array($s['source']??'',['nvd','kev','msrc','cisa-advisories','cisco-advisories','bsi','cert-eu'],true)){$has_cve=true;$technical=$technical||($has_text&&(!empty($s['cvss'])||!empty($s['cwe'])));}
 }
 $status='insufficient';$format=null;
 if(!$dated){$missing[]='Dated substantive source text and identifiable event/context.';}
 if(!$fragments){$missing[]='Attributable evidence fragments.';}
 if($dated&&$fragments){$status='limited';$format='attributed_source_summary';}
 if($template==='news'){
  if(!$official){$missing[]='Substantive dated official announcement for a news brief.';}
  elseif($dated&&$fragments){$status='sufficient';$format='news_brief';}
 }elseif($template==='vulnerability'){
  if(!$has_cve){$missing[]='CVE identifiers confirmed in official local vulnerability records.';}
  if(!$technical){$missing[]='Official technical impact/metric context; never invent CVSS or exploitation.';}
  if($dated&&$has_cve&&$technical&&$fragments){$status='sufficient';$format='bounded_vulnerability_metadata_analysis';}
 }else{
  $missing[]=$template==='paper'?'Research methodology, experiments/results and limitations beyond an abstract.':($template==='ai'?'Technical threat model, demonstrated behavior and study limitations.':'Attributable observations and technical campaign/context evidence.');
  // Full text alone is not proof the required semantic context exists. Human evidence review
  // is intentionally required before accepting deep analysis in this no-LLM stage.
  if(!$full){$missing[]='Complete relevant technical text, not merely a feed summary/abstract.';}
 }
 return ['schema'=>'cyberdat-evidence-gate/1','template'=>$template,'status'=>$status,'allowed_format'=>$format,'deep_analysis_allowed'=>false,'generation_allowed'=>$status==='sufficient','missing_fields'=>$missing,'reasons'=>['Deterministic evidence availability gate, not truth verification.','Sources may repeat the same publisher claim; independence is not assumed.'],'human_review_required'=>true];
}
