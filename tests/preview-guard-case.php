<?php
/** Isolated process per constants matrix case; no WP/bootstrap/network/database. */
$c=json_decode($argv[1],true,32,JSON_THROW_ON_ERROR);
define('ABSPATH',$c['path']??'/wordpress/');
foreach(['CYBERDAT_PLAYGROUND'=>'playground','CYBERDAT_STAGING_PREVIEW'=>'preview','CYBERDAT_KEV_LIVE'=>'kev','CYBERDAT_NVD_LIVE'=>'nvd'] as $constant=>$key){if(array_key_exists($key,$c)){define($constant,$c[$key]);}}
if(isset($c['auth'])){$_SERVER['REMOTE_USER']=$c['auth'];}
$_SERVER['HTTP_REMOTE_USER']='forged';$_GET['CYBERDAT_STAGING_PREVIEW']='true';
function wp_get_environment_type(){global $c;return $c['env']??'production';}
function home_url($path=''){global $c;return $c['home']??'https://staging.cyberdat.eu/';}
function site_url($path=''){global $c;return $c['site']??'https://staging.cyberdat.eu/';}
function wp_parse_url($url){return parse_url($url);}
$GLOBALS['hooks']=[];
function add_action($hook,$callback,...$args){$GLOBALS['hooks'][$hook]=$callback;}
function add_filter($hook,$callback,...$args){$GLOBALS['hooks'][$hook]=$callback;}
function get_header(){echo 'PREVIEW_HEADER';}
function get_footer(){}
function __($s,$domain=null){return $s;}
function esc_html_e($s,$domain=null){echo htmlspecialchars($s,ENT_QUOTES,'UTF-8');}
function get_template_part(...$args){}
function cyberdat_editorial_section(...$args){}
function is_front_page(){return true;}
function get_theme_file_uri($path){return $path;}
function get_theme_file_path($path){return '/nonexistent-guard-test'.$path;}
function wp_get_theme(){return new class{function get($name){return 'test';}};}
$GLOBALS['styles']=[];
function wp_enqueue_style($handle,...$args){$GLOBALS['styles'][]=$handle;}
function wp_enqueue_script(...$args){}
$theme=__DIR__.'/../wp-content/themes/cyberdat';
require $theme.'/inc/preview-guard.php';
require $theme.'/inc/kev-data.php';require $theme.'/inc/nvd-data.php';require $theme.'/inc/assets.php';
cyberdat_theme_enqueue_assets();
$dir=sys_get_temp_dir().'/cyberdat-preview-guard-'.bin2hex(random_bytes(6));mkdir($dir);
try{
 file_put_contents($dir.'/front-page.php',file_get_contents($theme.'/front-page.php'));
 file_put_contents($dir.'/index.php','<?php echo "SAFE_INDEX";');
 ob_start();include $dir.'/front-page.php';$html=ob_get_clean();
}finally{unlink($dir.'/front-page.php');unlink($dir.'/index.php');rmdir($dir);}
$before=array_keys($GLOBALS['hooks']);require __DIR__.'/../deploy/staging/wordpress/cyberdat-staging-safety.php.template';
$blocked_mail=isset($GLOBALS['hooks']['pre_wp_mail']) && ($GLOBALS['hooks']['pre_wp_mail'])(null)===false;
$robots=isset($GLOBALS['hooks']['wp_robots'])?($GLOBALS['hooks']['wp_robots'])(['index'=>true,'follow'=>true]):[];
echo json_encode(['allowed'=>cyberdat_home_preview_allowed(),'html_preview'=>str_contains($html,'PREVIEW_HEADER'),'safe_index'=>$html==='SAFE_INDEX','css'=>in_array('cyberdat-home-prototype',$GLOBALS['styles'],true),'kev'=>cyberdat_kev_live_enabled(),'nvd'=>cyberdat_nvd_live_enabled(),'mail_block'=>$blocked_mail,'robots'=>$robots]),"\n";
