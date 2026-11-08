<?php
/** Load a byte-exact official snapshot ONLY in the browser sandbox. */
require '/wordpress/wp-load.php';
if(!defined('CYBERDAT_PLAYGROUND') || !CYBERDAT_PLAYGROUND || ABSPATH!=='/wordpress/'){throw new RuntimeException('Playground guard failed');}
$dir=ABSPATH.'wp-content/cyberdat-preview/';
$meta=json_decode(file_get_contents($dir.'kev-provenance.json'),true,32,JSON_THROW_ON_ERROR);
$compressed=base64_decode(trim(file_get_contents($dir.'kev-snapshot.json.gz.b64')),true);
$raw=$compressed===false?false:gzdecode($compressed,4194305);
if($raw===false || hash('sha256',$raw)!==$meta['sha256']){throw new RuntimeException('Official snapshot checksum mismatch');}
$catalog=cyberdat_kev_validate($raw);
if(is_wp_error($catalog)){throw new RuntimeException($catalog->get_error_code());}
$at=(new DateTimeImmutable($meta['retrieved_at']))->getTimestamp();
if(!cyberdat_kev_store($catalog,$meta['source_url'],$at,true)){throw new RuntimeException('Cannot import official snapshot');}
require $dir.'kev-cases.php';
$report=cyberdat_kev_test_suite($raw,$meta);
file_put_contents($dir.'kev-test-results.json',wp_json_encode(['environment'=>'Offline official snapshot; HTTP responses mocked','results'=>$report],JSON_PRETTY_PRINT));
echo wp_json_encode($report),"\n";
