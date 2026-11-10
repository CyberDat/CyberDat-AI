<?php
/** Execute the actual asset hook without WordPress bootstrap, network or DB. */
define('ABSPATH','/offline/');define('CDRA_DIR','/offline/cyberdat-research');
$GLOBALS['hooks']=[];$GLOBALS['stage']=true;$GLOBALS['cap']=true;$GLOBALS['screen']='';$GLOBALS['assets']=[];
function add_action($name,$fn){$GLOBALS['hooks'][$name][]=$fn;}
function cdra_staging(){return $GLOBALS['stage'];}function current_user_can($v){return $GLOBALS['cap'];}function get_current_screen(){return (object)['id'=>$GLOBALS['screen']];}
function plugins_url($path,$plugin){return 'https://staging.cyberdat.eu/wp-content/plugins/cyberdat-research/'.$path;}
function wp_enqueue_style(...$args){$GLOBALS['assets'][]=$args;}
require __DIR__.'/../wp-content/plugins/cyberdat-research/includes/discovery-admin.php';cdra_discovery_admin_hooks();
foreach(['toplevel_page_cyberdat-research'=>1,'cyberdat_page_cyberdat-sources'=>1,'dashboard'=>0,'edit-post'=>0] as $screen=>$expected){$GLOBALS['screen']=$screen;$GLOBALS['assets']=[];foreach($GLOBALS['hooks']['admin_enqueue_scripts'] as $hook){$hook();}if(count($GLOBALS['assets'])!==$expected){throw new RuntimeException('Wrong asset scope');}}
$GLOBALS['screen']='toplevel_page_cyberdat-research';$GLOBALS['stage']=false;$GLOBALS['assets']=[];foreach($GLOBALS['hooks']['admin_enqueue_scripts'] as $hook){$hook();}if($GLOBALS['assets']){throw new RuntimeException('Production assets enqueued');}
$GLOBALS['stage']=true;$GLOBALS['cap']=false;foreach($GLOBALS['hooks']['admin_enqueue_scripts'] as $hook){$hook();}if($GLOBALS['assets']){throw new RuntimeException('Unauthorized assets enqueued');}
echo "PASS: actual admin asset hook limited to two authorized staging screens; no frontend/other-admin/production enqueue\n";
