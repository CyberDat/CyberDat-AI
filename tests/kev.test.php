<?php
/** CLI KEV tests; network and storage are isolated doubles. */
require __DIR__.'/wp-double.php';
require __DIR__.'/../wp-content/themes/cyberdat/inc/kev-data.php';
require __DIR__.'/../wp-content/themes/cyberdat/inc/nvd-data.php';
require __DIR__.'/kev-cases.php';
$fixture=__DIR__.'/../preview/kev/';$raw=gzdecode(base64_decode(file_get_contents($fixture.'official-snapshot.json.gz.b64'),true));$meta=json_decode(file_get_contents($fixture.'provenance.json'),true);
$results=cyberdat_kev_test_suite($raw,$meta);
$GLOBALS['cd_environment']='production';
$disabled=cyberdat_kev_refresh();
$results[]=['test'=>'Production data service refuses refresh, store and display','status'=>is_wp_error($disabled) && $disabled->get_error_code()==='kev_disabled' && !cyberdat_kev_store([],cyberdat_kev_sources()[0],time()) && cyberdat_kev_view()['status']==='Unavailable'?'PASS':'FAIL'];
foreach($results as $r){echo $r['status'].' '.$r['test'].(isset($r['detail'])?' — '.$r['detail']:''),"\n";}
exit(count(array_filter($results,static fn($r)=>$r['status']!=='PASS'))?1:0);
