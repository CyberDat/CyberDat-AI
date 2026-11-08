<?php
require __DIR__.'/wp-double.php';
require __DIR__.'/../wp-content/themes/cyberdat/inc/kev-data.php';
require __DIR__.'/../wp-content/themes/cyberdat/inc/nvd-data.php';
require __DIR__.'/nvd-cases.php';
$r=__DIR__.'/../preview/';$raw=gzdecode(base64_decode(file_get_contents($r.'kev/official-snapshot.json.gz.b64'),true));$meta=json_decode(file_get_contents($r.'kev/provenance.json'),true);cyberdat_kev_store(cyberdat_kev_validate($raw),$meta['source_url'],time(),true);
$p=json_decode(file_get_contents($r.'nvd/provenance.json'),true);$fixtures=json_decode(gzdecode(base64_decode(file_get_contents($r.'nvd/responses.json.gz.b64'),true)),true);
$results=cyberdat_nvd_test_suite($fixtures,$p);$GLOBALS['cd_environment']='production';$disabled=cyberdat_nvd_worker();$results[]=['test'=>'Production NVD worker disabled','status'=>is_wp_error($disabled) && $disabled->get_error_code()==='nvd_disabled'?'PASS':'FAIL'];foreach($results as $result){echo $result['status'].' '.$result['test'].(isset($result['detail'])?' — '.$result['detail']:''),"\n";}exit(count(array_filter($results,static fn($r)=>$r['status']!=='PASS'))?1:0);
