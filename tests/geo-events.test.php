<?php
/** Isolated fixtures only. No database, telemetry or WordPress posts. */
define('ABSPATH','/var/www/cyberdat-staging/public/');define('DB_NAME','cyberdat_staging');
function apply_filters($name,$v){return $v;}function add_action(...$args){}function register_activation_hook(...$args){}function wp_get_environment_type(){return $GLOBALS['env']??'staging';}function home_url($p){return 'https://staging.cyberdat.eu'.$p;}
require __DIR__.'/../wp-content/plugins/cyberdat-geo-events/cyberdat-geo-events.php';
function check($ok,$name){if(!$ok)throw new RuntimeException($name);echo "PASS: $name\n";}
function reject($fn,$name){try{$fn();}catch(Throwable $error){check(true,$name);return;}throw new RuntimeException('Accepted invalid input: '.$name);}
$now=strtotime('2026-11-08T20:00:00Z');$sources=['fixture'=>['name'=>'TEST ONLY','hosts'=>['example.org']]];
$e=['event_id'=>'TEST-ONLY-1','source'=>'fixture','event_type'=>'exposure','observed_at'=>'2026-11-08T19:00:00Z','country'=>'ZZ','region'=>'TEST ONLY','latitude'=>12.3456,'longitude'=>-42.3456,'geo_type'=>'reported_area','confidence'=>'low','evidence_url'=>'https://example.org/test-only','verification_status'=>'verified','display_authorized'=>true];
$v=cdgeo_validate_event($e,$sources,$now);check($v['latitude']===12.3&&$v['longitude']===-42.3,'precise fixture coordinates rounded to one decimal');check(!array_key_exists('source_ip',$v),'public schema has no IP field');
foreach(['source_ip'=>'10.0.0.1','target_ip'=>'1.1.1.1','evidence_url'=>'https://localhost/test','confidence'=>'certain','latitude'=>91,'source'=>'unapproved','observed_at'=>'2027-01-01T00:00:00Z'] as $key=>$bad){$x=$e;$x[$key]=$bad;reject(static fn()=>cdgeo_validate_event($x,$sources,$now),'invalid/private/unapproved '.$key.' denied');}
foreach(['https://example.org/test?token=secret','http://example.org/test','https://user:password@example.org/test'] as $bad){$x=$e;$x['evidence_url']=$bad;reject(static fn()=>cdgeo_validate_event($x,$sources,$now),'unsafe evidence URL rejected');}
check(cdgeo_sources()===[],'no real geo sources connected by default');
foreach([['page'=>11],['per_page'=>101],['days'=>365],['source'=>'evil'],['zoom'=>99],['days'=>['30']]] as $input){reject(static fn()=>cdgeo_filters($input,$sources),'bounded map query rejects '.array_key_first($input));}
$query=cdgeo_filters(['days'=>'7','zoom'=>'2'],$sources);check($query['days']===7&&$query['zoom']===2,'allowed numeric query parameters normalized');
$v['source_name']='TEST ONLY';$e2=$v;$e2['event_id']='TEST-ONLY-2';$events=[$v,$e2];$clusters=cdgeo_clusters($events,1);check(count($clusters)===1&&$clusters[0]['count']===2&&count($clusters[0]['events'])===2,'fixture points cluster deterministically without inventing events');check(cdgeo_clusters([],6)===[],'empty input produces no markers');
check(cdgeo_project(0,0)===[500,250],'projection matches local land atlas');
check(!cdgeo_permission(),'anonymous REST request forbidden');$_SERVER['REMOTE_USER']='TEST-ONLY';check(cdgeo_permission(),'Basic Auth identity required in staging');$GLOBALS['env']='production';check(!cdgeo_permission(),'production endpoint refused even with identity');
check(!str_contains(file_get_contents(__DIR__.'/../wp-content/plugins/cyberdat-geo-events/store.php'),'wp_remote_'),'no external source fetcher introduced');
$GLOBALS['env']='staging';$empty=cdgeo_public(cdgeo_filters([],[]));check($empty['items']===[]&&$empty['sources']===[]&&$empty['live_available']===false&&$empty['mode']==='observed_events','unconnected public endpoint stays truly empty, never live');
echo "PASS: no fixture events saved to database or deployed map\n";
