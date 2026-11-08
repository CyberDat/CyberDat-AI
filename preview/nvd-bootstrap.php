<?php
/** Original NIST responses imported without network, inside Playground only. */
require '/wordpress/wp-load.php';
if(!defined('CYBERDAT_PLAYGROUND') || !CYBERDAT_PLAYGROUND || ABSPATH!=='/wordpress/'){throw new RuntimeException('Playground guard failed');}
$dir=ABSPATH.'wp-content/cyberdat-preview/';
$meta=json_decode(file_get_contents($dir.'nvd-provenance.json'),true,32,JSON_THROW_ON_ERROR);
$raw=gzdecode(base64_decode(trim(file_get_contents($dir.'nvd-responses.json.gz.b64')),true),2097152);
if($raw===false || hash('sha256',$raw)!==$meta['bundle_sha256']){throw new RuntimeException('NVD snapshot bundle checksum mismatch');}
$fixtures=json_decode($raw,true,32,JSON_THROW_ON_ERROR);
foreach($meta['requests'] as $item){
 $id=$item['cve_id'];if(!isset($fixtures[$id]) || hash('sha256',$fixtures[$id])!==$item['sha256']){throw new RuntimeException('NVD response checksum mismatch');}
 $record=cyberdat_nvd_parse($fixtures[$id],$id);
 if(is_wp_error($record) || !cyberdat_nvd_store($record,(new DateTimeImmutable($item['retrieved_at']))->getTimestamp(),true)){throw new RuntimeException('NVD fixture failed validation/import');}
}
require $dir.'nvd-cases.php';$results=cyberdat_nvd_test_suite($fixtures,$meta);
file_put_contents($dir.'nvd-test-results.json',wp_json_encode(['environment'=>'Official fixed NIST snapshot; HTTP mocked; NOT LIVE','results'=>$results],JSON_PRETTY_PRINT));
echo wp_json_encode($results),"\n";
