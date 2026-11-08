<?php
defined('ABSPATH') || exit;
function cdra_priority($record,$kev,$changed=false,$now=null){
 $now=$now??time();$points=0;$reasons=[];
 $add=static function($factor,$value,$explanation)use(&$points,&$reasons){$points+=$value;$reasons[]=['factor'=>$factor,'points'=>$value,'explanation'=>$explanation];};
 if($kev){$add('kev',40,'Confirmed in the current validated CISA KEV catalog; this is not an exploitation probability.');}
 $a=$record['assessment']??null;
 if($a&&in_array($a['version'],['3.0','3.1','4.0'],true)){$add('cvss',(int)round($a['score']*2),'Selected CVSS '.$a['version'].' base score '.$a['score'].' from '.$a['source'].'.');}
 elseif($a){$add('legacy_cvss',0,'CVSS '.$a['version'].' retained but excluded from cross-version priority scoring.');}
 $age=max(0,$now-cdra_time($record['source_updated']));$fresh=$age<=86400?15:($age<=604800?8:0);
 $add('freshness',$fresh,'Age is measured from the source update, not ingestion time.');
 $add('official_source',10,'Allowlisted official source: '.$record['source_name'].'.');
 if(strlen($record['summary'])>=80){$add('context',5,'Source provides descriptive context; completeness is not proof of exploitability.');}
 $text=strtolower($record['original_title'].' '.$record['summary']);$audience=[];
 foreach(['SOC'=>['ransomware','incident','active exploitation','malware'],'DevSecOps'=>['container','kubernetes','docker','pipeline','gitlab'],'Systems administration'=>['server','windows','linux','network','firewall'],'AI Security'=>['language model','prompt injection','machine learning','artificial intelligence']] as $label=>$terms){foreach($terms as $term){if(str_contains($text,$term)){$audience[]=$label;break;}}}
 if($audience){$add('audience',min(10,count($audience)*5),'Keyword-based relevance heuristic: '.implode(', ',$audience).'.');}
 if($changed){$add('source_update',10,'Normalized source content materially changed since the previous version.');}
 return ['score'=>min(100,$points),'reasons'=>$reasons,'audience'=>$audience,'kind'=>'editorial_heuristic_not_EPSS'];
}
