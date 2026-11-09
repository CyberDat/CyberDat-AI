<?php
/**
 * Plugin Name: CyberDat Threat Analytics
 * Description: Staging-only read adapter and paginated public-field drill-down for Research Agent data.
 * Version: 2.1.0
 * Requires PHP: 8.0
 */
defined('ABSPATH') || exit;
function cdta_staging(){return defined('DB_NAME')&&DB_NAME==='cyberdat_staging'&&wp_get_environment_type()==='staging'&&rtrim(ABSPATH,'/').'/'==='/var/www/cyberdat-staging/public/'&&home_url('/')==='https://staging.cyberdat.eu/'&&function_exists('cyberdat_research_dashboard');}
require_once __DIR__.'/query.php';
function cdta_permission(){return cdta_staging()&&isset($_SERVER['REMOTE_USER'])&&is_string($_SERVER['REMOTE_USER'])&&$_SERVER['REMOTE_USER']!=='';}
function cdta_response($request){
 try{$q=cdta_filters($request->get_params());$response=new WP_REST_Response(cdta_records($q),200);$response->header('Cache-Control','private, no-store');$response->header('X-Robots-Tag','noindex, nofollow');return $response;}
 catch(InvalidArgumentException $e){return new WP_Error('invalid_analytics_query','Invalid analytics filters.',['status'=>400]);}
 catch(UnexpectedValueException $e){return new WP_Error('analytics_updated','Data changed since the chart. Refresh the selection to use current data.',['status'=>409]);}
 catch(Throwable $e){return new WP_Error('analytics_busy','Verified analytics are updating or temporarily unavailable. Retry shortly.',['status'=>503]);}
}
add_action('rest_api_init',static function(){if(cdta_staging()){register_rest_route('cyberdat-analytics/v1','/records',['methods'=>'GET','callback'=>'cdta_response','permission_callback'=>'cdta_permission']);}});
register_activation_hook(__FILE__,static function(){if(!cdta_staging()){wp_die('Threat Analytics activation is staging-only.');}});
