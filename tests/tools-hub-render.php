<?php
/** Offline presentation fixture. No WordPress/database/bootstrap or actual tool readiness claim. */
define('ABSPATH',__DIR__.'/');
$theme=realpath(__DIR__.'/../wp-content/themes/cyberdat');
$fixture_mode=$argv[1]??'current';
$catalog=json_decode(file_get_contents($theme.'/inc/tools-catalog.json'),true,32,JSON_THROW_ON_ERROR);
$ready_slugs=array_column(array_filter($catalog,static fn($t)=>$t['status']==='available'),'slug');
if($fixture_mode==='future'){
 // In-memory simulation only: no real catalogue or fifth-tool files are changed.
 foreach($catalog as &$t){if($t['status']!=='available'&&empty($fixture_selected)){$t['status']='available';$ready_slugs[]=$t['slug'];$fixture_selected=true;}}unset($t);
}
if($fixture_mode==='none')$ready_slugs=[];
function wp_enqueue_style(...$args){}
function get_theme_file_uri($p){return '/wp-content/themes/cyberdat'.$p;}
function get_theme_file_path($p){return $GLOBALS['theme'].$p;}
function cyberdat_theme_asset_version($p){return 'offline-review';}
function get_header(){} function get_footer(){}
function have_posts(){static $run=0;return $run++===0;}
function the_post(){}
function post_class($s){echo 'class="'.htmlspecialchars($s,ENT_QUOTES,'UTF-8').'"';}
function esc_html($s){return htmlspecialchars((string)$s,ENT_QUOTES,'UTF-8');}
function esc_attr($s){return esc_html($s);}function esc_url($s){return esc_html($s);}
function esc_html__($s,...$x){return esc_html($s);}function esc_html_e($s,...$x){echo esc_html($s);}function esc_attr_e($s,...$x){echo esc_attr($s);}
function cyberdat_planned_tools(){return $GLOBALS['catalog'];}
function cyberdat_ready_tools(){return array_map(static fn($s)=>(object)['post_name'=>$s],$GLOBALS['ready_slugs']);}
function get_permalink($p){return '/tools/'.$p->post_name.'/';}
function cyberdat_tools_breadcrumbs(){echo '<nav aria-label="Breadcrumbs"><ol class="cyberdat-tool-breadcrumbs"><li><a href="/">Home</a></li><li aria-current="page">Tools</li></ol></nav>';}
function cyberdat_tool_related_links(){echo '<nav class="cyberdat-tool-related" aria-label="Related reading"><h2>Related CyberDat Tools</h2><ul><li><a href="/tools/log-anonymizer/">Privacy Shield Log Anonymizer</a></li></ul></nav>';}
require $theme.'/page-templates/tools.php';
