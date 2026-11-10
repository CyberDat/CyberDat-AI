<?php
defined('ABSPATH') || exit;
class CDRA_Discovery_Store {
 public $store; public $db; public $p;
 public function __construct($store=null){$this->store=$store??new CDRA_Store();$this->db=$this->store->db;$this->p=$this->store->prefix;}
 public function install(){
  cdra_need(cdra_staging(),'staging_only');require_once ABSPATH.'wp-admin/includes/upgrade.php';$c=$this->db->get_charset_collate();$p=$this->p;
  foreach([
   "CREATE TABLE {$p}discovery (item_id bigint unsigned NOT NULL, stream varchar(16) NOT NULL, topic_id char(64) NOT NULL, manual_group tinyint NOT NULL DEFAULT 0, metadata longtext NOT NULL, published datetime NOT NULL, PRIMARY KEY  (item_id), KEY stream_date (stream,published), KEY topic (topic_id)) ENGINE=InnoDB $c;",
   "CREATE TABLE {$p}categories (item_id bigint unsigned NOT NULL, category varchar(64) NOT NULL, PRIMARY KEY  (item_id,category), KEY category (category)) ENGINE=InnoDB $c;",
   "CREATE TABLE {$p}identifiers (kind varchar(32) NOT NULL, identifier varchar(256) NOT NULL, topic_id char(64) NOT NULL, PRIMARY KEY  (kind,identifier), KEY topic (topic_id)) ENGINE=InnoDB $c;",
   "CREATE TABLE {$p}discovery_audit (id bigint unsigned NOT NULL AUTO_INCREMENT, actor bigint unsigned NOT NULL, action varchar(32) NOT NULL, item_id bigint unsigned NOT NULL, before_data longtext NOT NULL, after_data longtext NOT NULL, created datetime NOT NULL, PRIMARY KEY  (id), KEY item_created (item_id,created)) ENGINE=InnoDB $c;"
  ] as $sql){dbDelta($sql);}
  foreach(['discovery','categories','identifiers','discovery_audit'] as $t){cdra_need($this->db->get_var($this->db->prepare('SHOW TABLES LIKE %s',$this->db->esc_like($p.$t)))===$p.$t,'discovery_schema');}
  $this->store->put('discovery_schema',1);
 }
 public function audit($action,$id,$before,$after,$actor=0){cdra_need($this->db->insert($this->p.'discovery_audit',['actor'=>$actor,'action'=>$action,'item_id'=>$id,'before_data'=>cdra_json($before),'after_data'=>cdra_json($after),'created'=>cdra_stamp()])!==false,'discovery_audit');}
 public function topic($record,$id){
  $old=$this->db->get_row($this->db->prepare("SELECT topic_id,manual_group FROM {$this->p}discovery WHERE item_id=%d",$id),ARRAY_A);
  if($old&&(int)$old['manual_group']){return $old['topic_id'];}
  $identifiers=[];foreach(['doi','arxiv_id','openalex_id','semantic_scholar_id'] as $k){if(!empty($record['paper'][$k])){$identifiers[$k]=mb_strtolower($record['paper'][$k]);}}
  $topics=[];foreach($identifiers as $kind=>$value){$t=$this->db->get_var($this->db->prepare("SELECT topic_id FROM {$this->p}identifiers WHERE kind=%s AND identifier=%s",$kind,$value));if($t){$topics[$t]=true;}}
  cdra_need(count($topics)<=1,'paper_identifier_conflict');$topic=$topics?array_key_first($topics):($old['topic_id']??hash('sha256','item:'.$id));
  // Titles alone never merge scientific papers. Only exact stable identifiers correlate versions.
  if(!$record['paper']&&!$old){
   $rows=$this->db->get_results($this->db->prepare("SELECT d.topic_id,i.payload FROM {$this->p}discovery d JOIN {$this->p}items i ON i.id=d.item_id WHERE d.stream<>%s AND d.published BETWEEN %s AND %s AND d.manual_group=0 ORDER BY d.item_id DESC LIMIT 100",'papers',cdra_stamp(cdra_time($record['published'])-259200),cdra_stamp(cdra_time($record['published'])+259200)),ARRAY_A);
   foreach($rows as $row){$candidate=json_decode($row['payload'],true,64,JSON_THROW_ON_ERROR);if(cdra_discovery_related($record,$candidate)){$topic=$row['topic_id'];break;}}
  }
  foreach($identifiers as $kind=>$value){$this->store->query($this->db->prepare("INSERT INTO {$this->p}identifiers (kind,identifier,topic_id) VALUES (%s,%s,%s) ON DUPLICATE KEY UPDATE identifier=VALUES(identifier)",$kind,$value,$topic));}
  return $topic;
 }
 public function persist($record){
  $identity=hash('sha256',$record['source_id']);$url=hash('sha256',$record['canonical_url']);
  $old=$this->db->get_row($this->db->prepare("SELECT id,payload FROM {$this->p}items WHERE source=%s AND (url_key=%s OR id IN (SELECT item_id FROM {$this->p}aliases WHERE source=%s AND source_key=%s)) LIMIT 1",$record['source'],$url,$record['source'],$identity),ARRAY_A);
  $id=$this->store->upsert($record);$stored=$this->db->get_var($this->db->prepare("SELECT payload FROM {$this->p}items WHERE id=%d",$id));cdra_need(is_string($stored),'discovery_read');$effective=json_decode($stored,true,64,JSON_THROW_ON_ERROR);if(cdra_time($effective['source_updated'])>cdra_time($record['source_updated'])){$record=$effective;}$topic=$this->topic($record,$id);$meta=$this->db->get_var($this->db->prepare("SELECT metadata FROM {$this->p}discovery WHERE item_id=%d",$id));$prior=$meta?json_decode($meta,true,64,JSON_THROW_ON_ERROR):[];
  $metadata=['authors'=>$record['authors'],'paper'=>$record['paper'],'publisher'=>$record['publisher'],'source_timezone'=>$record['source_timezone'],'original_url'=>$record['original_url'],'classification_reasons'=>$record['classification_reasons'],'tags'=>$record['tags'],'technologies'=>$record['technologies'],'manual_categories'=>$prior['manual_categories']??null];
  cdra_need($this->db->query($this->db->prepare("INSERT INTO {$this->p}discovery (item_id,stream,topic_id,metadata,published) VALUES (%d,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE topic_id=VALUES(topic_id),metadata=VALUES(metadata),published=VALUES(published)",$id,$record['stream'],$topic,cdra_json($metadata),cdra_stamp(cdra_time($record['published']))))!==false,'discovery_write');
  $this->categories($id,$metadata['manual_categories']??$record['categories']);
  if(!$old){$this->audit('discovered',$id,[],['topic'=>$topic,'source'=>$record['source']]);}
  return ['id'=>$id,'inserted'=>!$old,'duplicate'=>$old&&cdra_hash(json_decode($old['payload'],true))===cdra_hash($record),'topic'=>$topic];
 }
 public function categories($id,$categories){$this->store->query($this->db->prepare("DELETE FROM {$this->p}categories WHERE item_id=%d",$id));foreach($categories as $cat){cdra_need(in_array($cat,cdra_discovery_categories(),true),'invalid_category');cdra_need($this->db->insert($this->p.'categories',['item_id'=>$id,'category'=>$cat])!==false,'category_write');}}
 public function correct($id,$categories,$actor,$hash){
  $this->store->transaction(function()use($id,$categories,$actor,$hash){$item=$this->db->get_row($this->db->prepare("SELECT i.content_hash,d.metadata FROM {$this->p}items i JOIN {$this->p}discovery d ON d.item_id=i.id WHERE i.id=%d FOR UPDATE",$id),ARRAY_A);cdra_need($item&&hash_equals($item['content_hash'],$hash),'source_changed_reload');$m=json_decode($item['metadata'],true);$before=$m['manual_categories']??null;$m['manual_categories']=array_values(array_unique($categories));$this->categories($id,$m['manual_categories']);cdra_need($this->db->update($this->p.'discovery',['metadata'=>cdra_json($m)],['item_id'=>$id])!==false,'classification_write');$this->audit('classify',$id,$before,$m['manual_categories'],$actor);});
 }
 public function regroup($ids,$split,$actor){
  cdra_need(count($ids)>=($split?1:2)&&count($ids)<=25&&count($ids)===count(array_unique($ids)),'group_ids');foreach($ids as $id){cdra_need(is_int($id)&&$id>0,'group_ids');}
  $this->store->transaction(function()use($ids,$split,$actor){$in=implode(',',array_fill(0,count($ids),'%d'));$rows=$this->db->get_results($this->db->prepare("SELECT item_id,topic_id FROM {$this->p}discovery WHERE item_id IN ($in) ORDER BY item_id FOR UPDATE",...$ids),ARRAY_A);cdra_need(count($rows)===count($ids),'group_missing');$topic=hash('sha256','manual:'.bin2hex(random_bytes(16)));if(!$split){$assigned=(int)$this->db->get_var($this->db->prepare("SELECT COUNT(*) FROM {$this->p}items WHERE id IN ($in) AND editorial_status IN ('approved_for_draft','ready_for_content_agent')",...$ids));cdra_need($assigned<=1,'topic_already_assigned');}
   foreach($rows as $row){$next=$split?hash('sha256',$topic.':'.$row['item_id']):$topic;cdra_need($this->db->update($this->p.'discovery',['topic_id'=>$next,'manual_group'=>1],['item_id'=>$row['item_id']])!==false,'group_write');$this->audit($split?'split':'merge',(int)$row['item_id'],['topic'=>$row['topic_id']],['topic'=>$next],$actor);}
  });
 }
}
function cdra_discovery_related($a,$b){
 if($a['paper']||$b['paper']||$a['stream']!==$b['stream']){return false;}
 $tokens=static fn($s)=>array_values(array_unique(array_filter(preg_split('/[^\pL\pN]+/u',mb_strtolower($s)),static fn($v)=>mb_strlen($v)>3)));
 $x=$tokens($a['original_title']);$y=$tokens($b['original_title']);if(min(count($x),count($y))<6){return false;}
 $similar=count(array_intersect($x,$y))/max(1,count(array_unique(array_merge($x,$y))));
 // CVE is supporting context, never sufficient evidence of the same event.
 return $similar>=0.9&&abs(cdra_time($a['published'])-cdra_time($b['published']))<=259200;
}
/** Read-only, private CLI handoff. No worker, publication or network side effect. */
function cdra_discovery_handoff($limit=20){
 cdra_need(cdra_staging()&&defined('WP_CLI')&&WP_CLI,'private_cli_only');$s=new CDRA_Store();$limit=max(1,min(50,$limit));
 $rows=$s->db->get_results($s->db->prepare("SELECT i.*,d.topic_id,d.metadata,d.stream FROM {$s->prefix}items i JOIN {$s->prefix}discovery d ON d.item_id=i.id WHERE i.editorial_status=%s AND i.approved_hash=i.content_hash ORDER BY COALESCE(i.manual_priority,i.priority) DESC,i.id LIMIT %d",'ready_for_content_agent',$limit),ARRAY_A);$out=[];
 foreach($rows as $row){$r=json_decode($row['payload'],true);$m=json_decode($row['metadata'],true);$refs=$s->db->get_results($s->db->prepare("SELECT i.canonical_url,i.source,i.published FROM {$s->prefix}discovery d JOIN {$s->prefix}items i ON i.id=d.item_id WHERE d.topic_id=%s ORDER BY i.id LIMIT 50",$row['topic_id']),ARRAY_A);
  $out[]=['schema'=>'cyberdat-research-handoff/1','topic_id'=>$row['topic_id'],'subject'=>$r['original_title'],'content_type'=>$r['content_type'],'categories'=>$m['manual_categories']??$r['categories'],'priority'=>(int)($row['manual_priority']??$row['priority']),'references'=>$refs,'facts'=>['source_publication'=>$r['published'],'confirmed_kev_relationship'=>(bool)$row['kev_confirmed']],'unverified_claims'=>['All source narrative and abstracts require human verification; heuristic score is not validity or exploitation probability.'],'cves'=>$r['cve_ids'],'products'=>array_values(array_filter([$r['vendor'],$r['product']])),'paper'=>$m['paper'],'status'=>'ready_for_content_agent','read_only'=>true];
 }return $out;
}
