<?php
/** Separate-process identity guard; no WordPress bootstrap/network. */
[$script,$db,$environment,$root,$home,$auth,$expected]=$argv;define('ABSPATH',$root);define('DB_NAME',$db);
function wp_get_environment_type(){global $environment;return $environment;}function home_url($path){global $home;return $home;}function cyberdat_research_dashboard(){}function add_action(...$v){}function register_activation_hook(...$v){}
if($auth!=='missing'){$_SERVER['REMOTE_USER']=$auth==='array'?[]:$auth;}
require __DIR__.'/../wp-content/plugins/cyberdat-threat-analytics/cyberdat-threat-analytics.php';
if(cdta_permission()!==($expected==='yes')){throw new RuntimeException('Permission contract failed');}echo "PASS identity/Basic guard\n";
