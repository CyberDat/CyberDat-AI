<?php
defined('ABSPATH') || exit;
class CDRA_Store {
 public $metrics=[];
 public $db;public $prefix;
 public function __construct(){global $wpdb;$this->db=$wpdb;$this->prefix=$wpdb->prefix.'cdra_';}
 public static function install(){
  cdra_need(cdra_staging(),'staging_only');global $wpdb;require_once ABSPATH.'wp-admin/includes/upgrade.php';$p=$wpdb->prefix.'cdra_';$charset=$wpdb->get_charset_collate();
  $schemas=[
  "CREATE TABLE {$p}items (
  id bigint unsigned NOT NULL AUTO_INCREMENT,
  source varchar(32) NOT NULL,
  source_key char(64) NOT NULL,
  source_id text NOT NULL,
  url_key char(64) NOT NULL,
  canonical_url text NOT NULL,
  content_hash char(64) NOT NULL,
  payload longtext NOT NULL,
  source_updated datetime NOT NULL,
  published datetime NOT NULL,
  first_seen datetime NOT NULL,
  last_seen datetime NOT NULL,
  editorial_status varchar(32) NOT NULL DEFAULT 'new',
  priority int NOT NULL DEFAULT 0,
  manual_priority int DEFAULT NULL,
  approved_hash char(64) DEFAULT NULL,
  reasons text NOT NULL,
  severity varchar(32) NOT NULL DEFAULT 'Not rated',
  cvss_version varchar(8) DEFAULT NULL,
  active tinyint NOT NULL DEFAULT 1,
  kev_confirmed tinyint NOT NULL DEFAULT 0,
  changed tinyint NOT NULL DEFAULT 0,
  PRIMARY KEY  (id),
  UNIQUE KEY source_identity (source,source_key),
  UNIQUE KEY canonical_identity (source,url_key),
  KEY editorial_status (editorial_status,priority),
  KEY source_updated (source,source_updated),
  KEY content_hash (content_hash),
  KEY priority (priority),
  KEY source_active (source,active)
  ) ENGINE=InnoDB $charset;",
  "CREATE TABLE {$p}aliases (
  source varchar(32) NOT NULL,
  source_key char(64) NOT NULL,
  item_id bigint unsigned NOT NULL,
  PRIMARY KEY  (source,source_key),
  KEY item_id (item_id)
  ) ENGINE=InnoDB $charset;",
  "CREATE TABLE {$p}cves (
  item_id bigint unsigned NOT NULL,
  cve varchar(32) NOT NULL,
  PRIMARY KEY  (item_id,cve),
  KEY cve (cve)
  ) ENGINE=InnoDB $charset;",
  "CREATE TABLE {$p}state (
  state_key varchar(64) NOT NULL,
  payload longtext NOT NULL,
  PRIMARY KEY  (state_key)
  ) ENGINE=InnoDB $charset;",
  "CREATE TABLE {$p}logs (
  id bigint unsigned NOT NULL AUTO_INCREMENT,
  source varchar(32) NOT NULL,
  code varchar(64) NOT NULL,
  created datetime NOT NULL,
  PRIMARY KEY  (id),
  KEY created (created)
  ) ENGINE=InnoDB $charset;",
  "CREATE TABLE {$p}events (
  id bigint unsigned NOT NULL AUTO_INCREMENT,
  item_id bigint unsigned NOT NULL,
  actor bigint unsigned NOT NULL,
  old_status varchar(32) NOT NULL,
  new_status varchar(32) NOT NULL,
  old_priority int DEFAULT NULL,
  new_priority int DEFAULT NULL,
  created datetime NOT NULL,
  PRIMARY KEY  (id),
  KEY item_id (item_id),
  KEY created (created)
  ) ENGINE=InnoDB $charset;"
  ];
  foreach($schemas as $schema){dbDelta($schema);}
  foreach(['items','aliases','cves','state','logs','events'] as $table){cdra_need($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s',$wpdb->esc_like($p.$table)))===$p.$table,'schema_install');}
  $store=new self();$store->put('schema',1);
 }
 public function query($sql){$previous=$this->db->suppress_errors(true);try{$result=$this->db->query($sql);cdra_need($result!==false,'database_error');return $result;}finally{$this->db->suppress_errors($previous);}}
 public function transaction($callback){$metrics=$this->metrics;$this->query('START TRANSACTION');try{$result=$callback();$this->query('COMMIT');return $result;}catch(Throwable $e){$this->metrics=$metrics;$this->db->query('ROLLBACK');throw $e;}}
 public function get($key,$default=null){$previous=$this->db->suppress_errors(true);try{$text=$this->db->get_var($this->db->prepare("SELECT payload FROM {$this->prefix}state WHERE state_key=%s",$key));cdra_need(!$this->db->last_error,'database_read');return $text===null?$default:json_decode($text,true,64,JSON_THROW_ON_ERROR);}finally{$this->db->suppress_errors($previous);}}
 public function put($key,$value){$this->query($this->db->prepare("INSERT INTO {$this->prefix}state (state_key,payload) VALUES (%s,%s) ON DUPLICATE KEY UPDATE payload=VALUES(payload)",$key,cdra_json($value)));}
 public function mutate($key,$callback){return $this->transaction(function()use($key,$callback){$this->query($this->db->prepare("INSERT IGNORE INTO {$this->prefix}state (state_key,payload) VALUES (%s,%s)",$key,'[]'));$text=$this->db->get_var($this->db->prepare("SELECT payload FROM {$this->prefix}state WHERE state_key=%s FOR UPDATE",$key));$value=$callback(json_decode($text,true,64,JSON_THROW_ON_ERROR));$this->put($key,$value);return $value;});}
 public function count($source=null){return (int)$this->db->get_var($source?$this->db->prepare("SELECT COUNT(*) FROM {$this->prefix}items WHERE source=%s",$source):"SELECT COUNT(*) FROM {$this->prefix}items");}
 public function kev($cves){if(!$cves){return false;}$in=implode(',',array_fill(0,count($cves),'%s'));return (bool)$this->db->get_var($this->db->prepare("SELECT 1 FROM {$this->prefix}cves c JOIN {$this->prefix}items i ON i.id=c.item_id WHERE i.source='kev' AND i.active=1 AND c.cve IN ($in) LIMIT 1",...$cves));}
 public function upsert($record){
  $source=$record['source'];$identity=hash('sha256',$record['source_id']);$url=hash('sha256',$record['canonical_url']);
  $existing=$this->db->get_results($this->db->prepare("SELECT * FROM {$this->prefix}items WHERE source=%s AND (id IN (SELECT item_id FROM {$this->prefix}aliases WHERE source=%s AND source_key=%s) OR url_key=%s) FOR UPDATE",$source,$source,$identity,$url),ARRAY_A);
  cdra_need(count($existing)<=1,'ambiguous_identity');$old=$existing[0]??null;
  if(!$old){cdra_need($this->count()<12000&&($source!=='nvd'||$this->count('nvd')<5000),'storage_capacity');}
  if($old&&$source==='kev'){$previous_record=json_decode($old['payload'],true,64,JSON_THROW_ON_ERROR);if(cdra_hash($previous_record['cisa_original'])===cdra_hash($record['cisa_original'])){$record['source_updated']=$previous_record['source_updated'];$record['source_updated_basis']=$previous_record['source_updated_basis'];}else{$record['source_updated']=$record['catalog_release'];$record['source_updated_basis']='catalog release containing an observed item change; exact item modification time unavailable';}}
  $text=cdra_json($record);cdra_need(strlen($text)<=131072,'item_size');$hash_record=$record;unset($hash_record['catalog_release']);$hash=cdra_hash($hash_record);

  if($old&&strtotime($old['source_updated'].' UTC')>cdra_time($record['source_updated'])){$this->metric($source,'stale');return (int)$old['id'];}
  $changed=$old&&$old['content_hash']!==$hash;
  $priority=(!empty($record['stream'])?'cdra_discovery_priority':'cdra_priority')($record,$record['source']==='kev'?true:$this->kev($record['cve_ids']),$changed||!empty($old['changed']));
  $a=$record['assessment']??null;
  $values=['source'=>$source,'source_key'=>$identity,'source_id'=>$record['source_id'],'url_key'=>$url,'canonical_url'=>$record['canonical_url'],'content_hash'=>$hash,'payload'=>$text,'source_updated'=>cdra_stamp(cdra_time($record['source_updated'])),'published'=>cdra_stamp(cdra_time($record['published'])),'last_seen'=>cdra_stamp(),'priority'=>$priority['score'],'reasons'=>cdra_json($priority),'severity'=>$a?$a['severity']:'Not rated','cvss_version'=>$a['version']??null,'active'=>1,'kev_confirmed'=>$record['source']==='kev'||$this->kev($record['cve_ids'])?1:0,'changed'=>($changed||!empty($old['changed']))?1:0];
  if($changed&&in_array($old['editorial_status'],['approved_for_draft','ready_for_content_agent'],true)){$values['editorial_status']='under_review';$values['approved_hash']=null;}
  $previous=$this->db->suppress_errors(true);
  try{
   if($old){$result=$this->db->update($this->prefix.'items',$values,['id'=>$old['id']]);$id=(int)$old['id'];}
   else{$values['first_seen']=cdra_stamp();$result=$this->db->insert($this->prefix.'items',$values);$id=(int)$this->db->insert_id;}
   cdra_need($result!==false&&$id>0,'item_write');
   if($changed&&in_array($old['editorial_status'],['approved_for_draft','ready_for_content_agent'],true)){cdra_need($this->db->insert($this->prefix.'events',['item_id'=>$id,'actor'=>0,'old_status'=>$old['editorial_status'],'new_status'=>'under_review','old_priority'=>$old['manual_priority'],'new_priority'=>$old['manual_priority'],'created'=>cdra_stamp()])!==false,'approval_invalidation_audit');}
  }finally{$this->db->suppress_errors($previous);}
  $this->query($this->db->prepare("INSERT INTO {$this->prefix}aliases (source,source_key,item_id) VALUES (%s,%s,%d) ON DUPLICATE KEY UPDATE item_id=VALUES(item_id)",$source,$identity,$id));
  $this->query($this->db->prepare("DELETE FROM {$this->prefix}cves WHERE item_id=%d",$id));
  foreach($record['cve_ids'] as $cve){$this->query($this->db->prepare("INSERT INTO {$this->prefix}cves (item_id,cve) VALUES (%d,%s)",$id,$cve));}
  $this->metric($source,!$old?'inserted':($changed?'updated':'unchanged'));
  return $id;
 }
 public function reprioritize(){
  for($offset=0;$offset<12000;$offset+=100){$rows=$this->db->get_results($this->db->prepare("SELECT id,payload,changed FROM {$this->prefix}items ORDER BY id LIMIT 100 OFFSET %d",$offset),ARRAY_A);if(!$rows){break;}
   foreach($rows as $row){$r=json_decode($row['payload'],true,64,JSON_THROW_ON_ERROR);$p=(!empty($r['stream'])?'cdra_discovery_priority':'cdra_priority')($r,$this->kev($r['cve_ids']),(bool)$row['changed']);$this->query($this->db->prepare("UPDATE {$this->prefix}items SET priority=%d,reasons=%s,kev_confirmed=%d WHERE id=%d",$p['score'],cdra_json($p),$this->kev($r['cve_ids'])?1:0,$row['id']));}
  }
 }
 public function metric($source,$kind){$this->metrics[$source][$kind]=($this->metrics[$source][$kind]??0)+1;if($kind==='inserted'){$this->metrics[$source]['last_new_item']=time();}}
 public function log($source,$code){cdra_need((isset(cdra_sources()[$source])||isset(cdra_discovery_registry()[$source]))&&preg_match('/^[a-z0-9_]{1,64}$/D',$code),'unsafe_log');$this->query($this->db->prepare("INSERT INTO {$this->prefix}logs (source,code,created) VALUES (%s,%s,%s)",$source,$code,cdra_stamp()));$this->query("DELETE FROM {$this->prefix}logs WHERE created < UTC_TIMESTAMP()-INTERVAL 30 DAY LIMIT 500");$cut=(int)$this->db->get_var("SELECT id FROM {$this->prefix}logs ORDER BY id DESC LIMIT 1 OFFSET 4999");if($cut){$this->query($this->db->prepare("DELETE FROM {$this->prefix}logs WHERE id<%d LIMIT 1000",$cut));}}
 public function editorial($id,$status,$priority,$actor,$expected){
  cdra_need(isset(cdra_statuses()[$status])&&($priority===null||(is_int($priority)&&$priority>=0&&$priority<=100)),'invalid_editorial_input');
  $this->transaction(function()use($id,$status,$priority,$actor,$expected){$old=$this->db->get_row($this->db->prepare("SELECT editorial_status,manual_priority,content_hash FROM {$this->prefix}items WHERE id=%d FOR UPDATE",$id),ARRAY_A);cdra_need($old!==null,'item_not_found');cdra_need(hash_equals($old['content_hash'],$expected),'source_changed_reload');
   if(in_array($status,['approved_for_draft','ready_for_content_agent'],true)&&$this->get('discovery_schema')===1){$topic=$this->db->get_var($this->db->prepare("SELECT topic_id FROM {$this->prefix}discovery WHERE item_id=%d",$id));if($topic){$assigned=$this->db->get_results($this->db->prepare("SELECT i.id,i.editorial_status FROM {$this->prefix}items i JOIN {$this->prefix}discovery d ON d.item_id=i.id WHERE d.topic_id=%s ORDER BY i.id FOR UPDATE",$topic),ARRAY_A);foreach($assigned as $peer){cdra_need((int)$peer['id']===$id||!in_array($peer['editorial_status'],['approved_for_draft','ready_for_content_agent'],true),'topic_already_assigned');}}}

   $previous=$this->db->suppress_errors(true);try{cdra_need($this->db->update($this->prefix.'items',['editorial_status'=>$status,'manual_priority'=>$priority,'approved_hash'=>in_array($status,['approved_for_draft','ready_for_content_agent'],true)?$expected:null],['id'=>$id])!==false,'editorial_write');cdra_need($this->db->insert($this->prefix.'events',['item_id'=>$id,'actor'=>$actor,'old_status'=>$old['editorial_status'],'new_status'=>$status,'old_priority'=>$old['manual_priority'],'new_priority'=>$priority,'created'=>cdra_stamp()])!==false,'editorial_audit');}finally{$this->db->suppress_errors($previous);}
  });
 }
}
