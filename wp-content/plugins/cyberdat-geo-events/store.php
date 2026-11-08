<?php
defined('ABSPATH') || exit;
function cdgeo_table(){global $wpdb;return $wpdb->prefix.'cyberdat_geo_events';}
function cdgeo_install(){
 if(!cdgeo_staging()){throw new RuntimeException('staging_only');}global $wpdb;require_once ABSPATH.'wp-admin/includes/upgrade.php';$table=cdgeo_table();$collation=$wpdb->get_charset_collate();
 dbDelta("CREATE TABLE $table (
 id bigint unsigned NOT NULL AUTO_INCREMENT,
 event_id varchar(128) NOT NULL,
 event_key char(64) NOT NULL,
 source varchar(32) NOT NULL,
 event_type varchar(24) NOT NULL,
 observed_at datetime NOT NULL,
 latitude decimal(4,1) NOT NULL,
 longitude decimal(5,1) NOT NULL,
 verification_status varchar(16) NOT NULL,
 display_authorized tinyint NOT NULL DEFAULT 0,
 payload text NOT NULL,
 PRIMARY KEY  (id),
 UNIQUE KEY source_event (source,event_key),
 KEY public_observed (verification_status,display_authorized,observed_at),
 KEY source_observed (source,observed_at)
 ) ENGINE=InnoDB $collation;");
 if($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s',$wpdb->esc_like($table)))!==$table){throw new RuntimeException('Geo schema unavailable');}
}
/** Future reviewed CLI connector only. No automatic ingestion or write endpoint. */
function cdgeo_upsert($input){
 if(!cdgeo_staging()||!defined('WP_CLI')||!WP_CLI||!current_user_can('manage_options')){throw new RuntimeException('CLI administrator required');}
 $e=cdgeo_validate_event($input,cdgeo_sources());global $wpdb;$table=cdgeo_table();$payload=wp_json_encode($e);$result=$wpdb->query($wpdb->prepare("INSERT INTO $table (event_id,event_key,source,event_type,observed_at,latitude,longitude,verification_status,display_authorized,payload) VALUES (%s,%s,%s,%s,%s,%f,%f,%s,%d,%s) ON DUPLICATE KEY UPDATE event_type=VALUES(event_type),observed_at=VALUES(observed_at),latitude=VALUES(latitude),longitude=VALUES(longitude),verification_status=VALUES(verification_status),display_authorized=VALUES(display_authorized),payload=VALUES(payload)",$e['event_id'],hash('sha256',$e['event_id']),$e['source'],$e['event_type'],str_replace(['T','Z'],[' ',''],$e['observed_at']),$e['latitude'],$e['longitude'],$e['verification_status'],$e['display_authorized']?1:0,$payload));
 if($result===false){throw new RuntimeException('Geo storage failed');}delete_transient('cyberdat_geo_snapshot');
}
function cdgeo_snapshot(){
 $sources=cdgeo_sources();if(!$sources){return ['events'=>[],'truncated'=>false,'generated_at'=>time()];}
 $cache=get_transient('cyberdat_geo_snapshot');$signature=hash('sha256',wp_json_encode($sources));if(is_array($cache)&&($cache['signature']??'')===$signature){return $cache;}
 global $wpdb;$table=cdgeo_table();$previous=$wpdb->suppress_errors(true);
 try{$in=implode(',',array_fill(0,count($sources),'%s'));$sql=$wpdb->prepare("SELECT payload FROM $table WHERE source IN ($in) AND verification_status='verified' AND display_authorized=1 AND observed_at>=UTC_TIMESTAMP()-INTERVAL 90 DAY ORDER BY observed_at DESC,id DESC LIMIT 1001",...array_keys($sources));$rows=$wpdb->get_results($sql,ARRAY_A);if($wpdb->last_error){throw new RuntimeException('Geo data unavailable');}}finally{$wpdb->suppress_errors($previous);}
 $events=[];foreach(array_slice($rows,0,1000) as $row){try{$event=cdgeo_validate_event(json_decode($row['payload'],true,32,JSON_THROW_ON_ERROR),$sources);if($event['verification_status']==='verified'&&$event['display_authorized']){$event['source_name']=$sources[$event['source']]['name'];unset($event['display_authorized']);$events[]=$event;}}catch(InvalidArgumentException|JsonException $e){continue;}}
 $cache=['events'=>$events,'truncated'=>count($rows)>1000,'generated_at'=>time(),'signature'=>$signature];set_transient('cyberdat_geo_snapshot',$cache,60);return $cache;
}
function cdgeo_public($query){
 if(!cdgeo_staging()){throw new RuntimeException('staging_only');}$snapshot=cdgeo_snapshot();$sources=cdgeo_sources();$cut=time()-$query['days']*86400;
 $events=array_values(array_filter($snapshot['events'],static fn($e)=>strtotime($e['observed_at'])>=$cut&&($query['event_type']==='all'||$e['event_type']===$query['event_type'])&&($query['source']==='all'||$e['source']===$query['source'])));
 $items=$query['format']==='clusters'?cdgeo_clusters($events,$query['zoom']):$events;$total=count($items);$start=($query['page']-1)*$query['per_page'];
 return ['schema'=>1,'mode'=>'observed_events','live_available'=>false,'sources'=>array_map(static fn($s)=>['name'=>$s['name']],$sources),'items'=>array_slice($items,$start,$query['per_page']),'matched_events'=>count($events),'total_items'=>$total,'page'=>$query['page'],'per_page'=>$query['per_page'],'has_more'=>$start+$query['per_page']<$total,'coverage_limited'=>$snapshot['truncated'],'snapshot_limit'=>1000,'generated_at'=>gmdate('Y-m-d\TH:i:s\Z',$snapshot['generated_at']),'geolocation_notice'=>'Approximate location is not evidence of attacker origin.','empty_message'=>'No verified geolocated threat events available.'];
}
