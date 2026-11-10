<?php
/** CLI-only fixtures; all tables TEMPORARY and uniquely prefixed. No real queue writes. */
function cdra_discovery_database_tests(){
 cdra_need(cdra_staging()&&defined('WP_CLI')&&WP_CLI,'staging_cli_only');$s=new CDRA_Store();$real=$s->prefix;$s->prefix=$real.'dtest_'.bin2hex(random_bytes(4)).'_';$tables=['items','aliases','cves','state','logs','events','discovery','categories','identifiers','discovery_audit'];$created=[];$checks=0;
 $check=static function($ok,$label)use(&$checks){cdra_need($ok,'discovery_self_test');++$checks;WP_CLI::line('PASS: '.$label);};
 try{
  foreach($tables as $table){$s->query("CREATE TEMPORARY TABLE {$s->prefix}$table LIKE {$real}$table");$created[]=$table;}
  $s->put('discovery_schema',1);$ds=new CDRA_Discovery_Store($s);
  $r=cdra_discovery_record('talos','TEST-one','https://blog.talosintelligence.com/test-only','TEST Independent Ransomware Campaign Targets Enterprise Network Defenders','TEST ONLY CVE-2020-0001 malware','2020-01-01T12:00:00Z');
  $a=$s->transaction(static fn()=>$ds->persist($r));$again=$s->transaction(static fn()=>$ds->persist($r));$check($a['id']===$again['id']&&$s->count()===1&&$again['duplicate'],'same source repeated import is idempotent');
  $alias=$r;$alias['source_id']='TEST-alias';$s->transaction(static fn()=>$ds->persist($alias));$check($s->count()===1,'canonical duplicate creates alias not another publication');
  $other=$r;$other['source']='unit42';$other['source_name']=cdra_spec('unit42')['name'];$other['source_id']='TEST-two';$other['canonical_url']='https://unit42.paloaltonetworks.com/test-only';$other['publisher']='Palo Alto Networks';$b=$s->transaction(static fn()=>$ds->persist($other));$check($s->count()===2&&$a['topic']===$b['topic'],'related coverage preserves independent publications in one topic');
  $different=$other;$different['source_id']='TEST-three';$different['canonical_url'].='-different';$different['original_title']='TEST Completely Separate Event With The Same CVE';$c=$s->transaction(static fn()=>$ds->persist($different));$check($c['topic']!==$a['topic'],'common CVE alone does not merge unrelated events');
  $hash=$s->db->get_var($s->db->prepare("SELECT content_hash FROM {$s->prefix}items WHERE id=%d",$a['id']));$ds->correct($a['id'],['Malware'],1,$hash);$s->transaction(static fn()=>$ds->persist($r));$cats=$s->db->get_col($s->db->prepare("SELECT category FROM {$s->prefix}categories WHERE item_id=%d",$a['id']));$check($cats===['Malware'],'manual classification persists across re-ingestion');
  // The preceding import restored the original source ID after the alias test.
  // Keep the stale-form rejection assertion, then reload current evidence for approval.
  $stale_hash=$hash;$hash=$s->db->get_var($s->db->prepare("SELECT content_hash FROM {$s->prefix}items WHERE id=%d",$a['id']));
  try{$s->editorial($a['id'],'ready_for_content_agent',88,1,$stale_hash);throw new RuntimeException('Stale fixture review accepted');}catch(CDRA_Error $e){$check($e->getMessage()==='source_changed_reload'&&$hash!==$stale_hash,'stale alias evidence rejected before fresh review');}
  $s->editorial($a['id'],'ready_for_content_agent',88,1,$hash);$otherhash=$s->db->get_var($s->db->prepare("SELECT content_hash FROM {$s->prefix}items WHERE id=%d",$b['id']));
  try{$s->editorial($b['id'],'approved_for_draft',null,1,$otherhash);throw new RuntimeException('Duplicate assignment accepted');}catch(CDRA_Error $e){$check($e->getMessage()==='topic_already_assigned','duplicate editorial assignment prevented per topic');}
  $ds->regroup([$b['id']],true,1);$topic=$s->db->get_var($s->db->prepare("SELECT topic_id FROM {$s->prefix}discovery WHERE item_id=%d",$b['id']));$s->transaction(static fn()=>$ds->persist($other));$check($topic===$s->db->get_var($s->db->prepare("SELECT topic_id FROM {$s->prefix}discovery WHERE item_id=%d",$b['id']))&&$topic!==$a['topic'],'manual split survives automatic re-ingestion');
  $paper=cdra_discovery_record('arxiv','2001.12345','https://arxiv.org/abs/2001.12345','TEST security paper','TEST abstract','2020-01-01T00:00:00Z',null,['paper'=>['doi'=>'10.1234/test','arxiv_id'=>'2001.12345','openalex_id'=>null,'semantic_scholar_id'=>null,'venue'=>null,'review_status'=>'Preprint','abstract'=>'TEST abstract','code_url'=>null]]);$p1=$s->transaction(static fn()=>$ds->persist($paper));
  $paper2=$paper;$paper2['source']='crossref';$paper2['source_name']='Crossref';$paper2['source_id']='10.1234/test';$paper2['canonical_url']='https://doi.org/10.1234/test';$paper2['paper']['arxiv_id']=null;$paper2['paper']['review_status']='Unknown';$p2=$s->transaction(static fn()=>$ds->persist($paper2));$check($p1['topic']===$p2['topic']&&$p1['id']!==$p2['id'],'scientific DOI matching preserves both providers and revisions');
  $before=$s->count();try{$s->transaction(function()use($ds,$different){$different['source_id']='TEST-rollback';$different['canonical_url'].='-rollback';$ds->persist($different);throw new CDRA_Error('test_rollback');});}catch(CDRA_Error $e){}$check($s->count()===$before,'DB failure rolls back record/category/topic writes');
  $check((int)$s->db->get_var("SELECT COUNT(*) FROM {$s->prefix}discovery_audit")>=5,'classification/grouping/discovery audit persisted');
  WP_CLI::success($checks.' temporary-table discovery checks; no live ingestion or WordPress posts.');
 }finally{foreach(array_reverse($created) as $table){$s->db->query("DROP TEMPORARY TABLE {$s->prefix}$table");}}
}
