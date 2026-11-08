<?php
/**
 * Plugin Name: CyberDat Threat Geo Events
 * Description: Staging-only verified approximate geographic events. No telemetry sources or ingestion enabled.
 * Version: 0.1.0
 * Requires PHP: 8.0
 */
defined('ABSPATH') || exit;
function cdgeo_staging(){return defined('DB_NAME')&&DB_NAME==='cyberdat_staging'&&wp_get_environment_type()==='staging'&&rtrim(ABSPATH,'/').'/'==='/var/www/cyberdat-staging/public/'&&home_url('/')==='https://staging.cyberdat.eu/';}
require_once __DIR__.'/model.php';
require_once __DIR__.'/store.php';
function cdgeo_permission(){return cdgeo_staging()&&isset($_SERVER['REMOTE_USER'])&&is_string($_SERVER['REMOTE_USER'])&&$_SERVER['REMOTE_USER']!=='';}
function cdgeo_response($request){
 try{$query=cdgeo_filters($request->get_params(),cdgeo_sources());$response=new WP_REST_Response(cdgeo_public($query),200);$response->header('Cache-Control','private, max-age=60');$response->header('X-Robots-Tag','noindex, nofollow');return $response;}catch(InvalidArgumentException $e){return new WP_Error('invalid_geo_query','Invalid map filters.',['status'=>400]);}catch(Throwable $e){return new WP_Error('geo_unavailable','Verified geo events are temporarily unavailable.',['status'=>503]);}
}
add_action('rest_api_init',static function(){if(cdgeo_staging()){register_rest_route('cyberdat-geo/v1','/events',['methods'=>'GET','callback'=>'cdgeo_response','permission_callback'=>'cdgeo_permission']);}});
register_activation_hook(__FILE__,static function(){if(!cdgeo_staging()){wp_die('Geo Events activation is staging-only.');}cdgeo_install();});
