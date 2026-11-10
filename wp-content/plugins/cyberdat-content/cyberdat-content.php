<?php
/**
 * Plugin Name: CyberDat Content Queue
 * Description: Staging preparation, private pull worker and explicitly marked mock drafts. Never publishes posts.
 * Version: 0.9.0
 * Requires PHP: 8.0
 */
defined('ABSPATH') || exit;
define('CDCA_DIR',__DIR__);
function cdca_stage(){return function_exists('cdra_staging')&&cdra_staging();}
foreach(['contracts','research','store','api','admin','cli'] as $module){require_once __DIR__.'/includes/'.$module.'.php';}
register_activation_hook(__FILE__,static function(){if(!cdca_stage()){wp_die('Staging Research Agent required.');}CDCA_Store::install();});
add_action('plugins_loaded',static function(){if(cdca_stage()){cdca_admin_hooks();add_action('rest_api_init','cdca_routes');}});
