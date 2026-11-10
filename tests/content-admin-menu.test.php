<?php
/** Exercise installed WordPress menu/access code without WordPress DB/bootstrap. */
$core=$argv[1]??'/var/www/cyberdat-staging/public';define('ABSPATH',$core.'/');define('WP_PLUGIN_DIR',$core.'/wp-content/plugins');define('WPMU_PLUGIN_DIR',$core.'/wp-content/mu-plugins');
$GLOBALS['wp_plugin_paths']=[];require $core.'/wp-includes/plugin.php';require $core.'/wp-admin/includes/plugin.php';
function wp_normalize_path($v){return str_replace('\\','/',$v);}function sanitize_title($v){return strtolower(preg_replace('/[^a-z0-9]+/i','-',$v));}function set_url_scheme($v){return $v;}function current_user_can($v){return $GLOBALS['allowed'];}
require __DIR__.'/../wp-content/plugins/cyberdat-content/includes/admin.php';require __DIR__.'/../wp-content/plugins/cyberdat-research/includes/admin.php';
foreach(['content_first','research_first','unauthorized'] as $case){
 foreach(['menu','submenu','admin_page_hooks','_registered_pages','_parent_pages','_wp_real_parent_file','_wp_menu_nopriv','_wp_submenu_nopriv'] as $v){$GLOBALS[$v]=[];}$GLOBALS['parent_file']='';$GLOBALS['typenow']='';$GLOBALS['pagenow']='admin.php';$GLOBALS['plugin_page']='cyberdat-content';$GLOBALS['allowed']=$case!=='unauthorized';$GLOBALS['wp_filter']=[];
 if($case==='research_first'){cdra_admin_hooks();cdca_admin_hooks();}else{cdca_admin_hooks();cdra_admin_hooks();}
 do_action('admin_menu');$can=user_can_access_admin_page();$expected=$case!=='unauthorized';
 if($can!==$expected){throw new RuntimeException('Content access registration failed: '.$case.'; actual expected hook='.get_plugin_page_hookname('cyberdat-content','cyberdat-research').'; registered='.implode(',',array_keys($GLOBALS['_registered_pages'])));}
 if($expected&&!has_action('cyberdat_page_cyberdat-content','cdca_admin_page')){throw new RuntimeException('Content callback not bound to actual parent hook');}
 echo 'PASS: actual WordPress menu/access lifecycle '.$case."\n";
}
