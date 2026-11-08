<?php
/**
 * Plugin Name: CyberDat Research Agent
 * Description: Staging-only official threat intelligence ingestion and human editorial queue. No LLM or publication.
 * Version: 0.8.1
 * Requires at least: 6.7
 * Requires PHP: 8.0
 * Text Domain: cyberdat-research
 */
defined('ABSPATH') || exit;
define('CDRA_DIR',__DIR__);
function cdra_staging(){return defined('DB_NAME')&&DB_NAME==='cyberdat_staging'&&wp_get_environment_type()==='staging' && rtrim(ABSPATH,'/').'/'==='/var/www/cyberdat-staging/public/' && get_option('home')==='https://staging.cyberdat.eu';}
foreach(['registry','legacy-validators','normalize','priority','storage','fetch','ingestion','dashboard','analytics','admin','cli'] as $file){require_once __DIR__.'/includes/'.$file.'.php';}
register_activation_hook(__FILE__,static function(){if(!cdra_staging()){wp_die('Research Agent activation is restricted to the approved staging installation.');}CDRA_Store::install();});
add_action('plugins_loaded',static function(){if(cdra_staging()){cdra_admin_hooks();}});
