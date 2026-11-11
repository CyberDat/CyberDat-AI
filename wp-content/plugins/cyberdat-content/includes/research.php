<?php
defined('ABSPATH') || exit;
/** Read-only adapter: selection is checked at both ends; no collector/state writes. */
function cdca_research_evidence($id,$require_selected=true) {
 cdca_need(cdca_stage()&&is_int($id)&&$id>0,'research_identity');global $wpdb;$p=$wpdb->prefix.'cdra_';
 $row=$wpdb->get_row($wpdb->prepare("SELECT i.*,d.topic_id,d.stream,d.metadata FROM {$p}items i LEFT JOIN {$p}discovery d ON d.item_id=i.id WHERE i.id=%d",$id),ARRAY_A);
 cdca_need($row&&!$wpdb->last_error,'research_missing');
 if($require_selected){cdca_need($row['editorial_status']==='ready_for_content_agent'&&hash_equals((string)$row['content_hash'],(string)$row['approved_hash']),'research_not_selected');}
 $topic=$row['topic_id']??hash('sha256','research-item:'.$id);
 $rows=empty($row['topic_id'])?[$row]:$wpdb->get_results($wpdb->prepare("SELECT i.*,d.topic_id,d.stream,d.metadata FROM {$p}items i JOIN {$p}discovery d ON d.item_id=i.id WHERE d.topic_id=%s ORDER BY i.id LIMIT 21",$topic),ARRAY_A);
 cdca_need(!$wpdb->last_error&&count($rows)>=1&&count($rows)<=20,'research_topic_bounds');
 $sources=[];$cves=[];$hashes=[];$subject='';foreach($rows as $r){$s=cdca_source_record($r,count($sources)+1);$sources[]=$s;$hashes[]=[(int)$r['id'],$r['content_hash'],hash('sha256',$r['metadata']??''),(int)$r['priority'],$r['manual_priority']];$cves=array_merge($cves,$s['cves']);if((int)$r['id']===$id){$subject=$s['title'];}}
 // Join existing official CVE data only; no external API call or historical import.
 $related=[];$unique=array_values(array_unique($cves));sort($unique);
 foreach(array_slice($unique,0,10) as $cve){
  $extra=$wpdb->get_results($wpdb->prepare("SELECT i.* FROM {$p}items i JOIN {$p}cves c ON c.item_id=i.id WHERE c.cve=%s AND i.source IN ('nvd','kev','msrc','cisa-advisories','cert-eu','cisco-advisories') ORDER BY i.id LIMIT 5",$cve),ARRAY_A);
  cdca_need(!$wpdb->last_error,'research_related');
  foreach($extra as $r){if(in_array((int)$r['id'],array_column($sources,'research_item_id'),true)){continue;}if(count($sources)>=20){break;}$s=cdca_source_record($r,count($sources)+1);$sources[]=$s;$hashes[]=[(int)$r['id'],$r['content_hash']];$related[]=$s['id'];}
 }
 $fresh=$wpdb->get_row($wpdb->prepare("SELECT i.content_hash,i.approved_hash,i.editorial_status,d.topic_id FROM {$p}items i LEFT JOIN {$p}discovery d ON d.item_id=i.id WHERE i.id=%d",$id),ARRAY_A);
 cdca_need($fresh&&$fresh['content_hash']===$row['content_hash']&&$fresh['topic_id']===$row['topic_id']&&(!$require_selected||($fresh['editorial_status']==='ready_for_content_agent'&&$fresh['approved_hash']===$row['approved_hash'])),'research_changed');
 $e=['topic_id'=>$topic,'research_item'=>$id,'source_hash'=>cdca_hash([$topic,$id,$hashes]),'subject'=>$subject,'sources'=>$sources,'cves'=>$unique,'related_official_sources'=>$related,'fragments'=>cdca_fragments($sources),'limitations'=>['Source claims remain unverified; primary-source and date review required.','Full text is not inferred from an RSS summary, abstract or multiple URLs.']];
 cdca_need(strlen(cdca_json($e))<=220000,'evidence_size');return $e;
}
function cdca_selected_evidence($id){return cdca_research_evidence($id,true);}
function cdca_research_current($job){if((int)$job['is_test']){return true;}try{$now=cdca_selected_evidence((int)$job['research_item']);return hash_equals($job['source_hash'],$now['source_hash']);}catch(Throwable $e){return false;}}
