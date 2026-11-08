<?php
/** CLI adapter only: no WordPress, network or real database is loaded. */
define('ABSPATH',__DIR__.'/');
$GLOBALS['cd_options']=[];$GLOBALS['cd_filters']=[];
class WP_Error {function __construct(public $code,public $message=''){}function get_error_code(){return $this->code;}}
function is_wp_error($v){return $v instanceof WP_Error;}
function wp_get_environment_type(){return $GLOBALS['cd_environment']??'local';}
function add_action(...$a){}
function get_option($k,$default=false){return $GLOBALS['cd_options'][$k]??$default;}
function update_option($k,$v,$autoload=null){$same=get_option($k,null)===$v;$GLOBALS['cd_options'][$k]=$v;return !$same;}
function add_option($k,$v,$deprecated='',$autoload=null){if(array_key_exists($k,$GLOBALS['cd_options'])){return false;}$GLOBALS['cd_options'][$k]=$v;return true;}
function delete_option($k){unset($GLOBALS['cd_options'][$k]);return true;}
function maybe_serialize($v){return serialize($v);}
function wp_cache_delete(...$args){}
function wp_generate_uuid4(){return bin2hex(random_bytes(16));}
class CD_Options_Double {public $options='mock_options';function prepare($sql,...$args){return $args;}function query($args){[$key,$value]=$args;if(serialize(get_option($key))===$value){delete_option($key);return 1;}return 0;}}
$GLOBALS['wpdb']=new CD_Options_Double;
function add_filter($hook,$callback,...$args){$GLOBALS['cd_filters'][$hook]=$callback;}
function remove_filter($hook,...$args){unset($GLOBALS['cd_filters'][$hook]);}
function wp_safe_remote_get($url,$args){return isset($GLOBALS['cd_filters']['pre_http_request'])?($GLOBALS['cd_filters']['pre_http_request'])(false,$args,$url):new WP_Error('offline');}
function wp_remote_retrieve_response_code($r){return $r['response']['code'];}
function wp_remote_retrieve_header($r,$h){return $r['headers'][$h]??'';}
function wp_remote_retrieve_body($r){return $r['body'];}
function wp_next_scheduled(...$a){return false;}
function wp_clear_scheduled_hook(...$a){}
function wp_schedule_event(...$a){throw new RuntimeException('Live cron unexpectedly enabled');}
function __($s,$domain=null){return $s;}
function esc_html($s){return htmlspecialchars((string)$s,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');}
function esc_attr($s){return esc_html($s);}
function esc_url($s){return esc_html($s);}
function esc_html_e($s,$domain=null){echo esc_html($s);}
function esc_attr_e($s,$domain=null){echo esc_attr($s);}
function number_format_i18n($v){return number_format($v);}
function get_template_part($path,$name=null,$args=[]){require __DIR__.'/../wp-content/themes/cyberdat/'.$path.'.php';}
