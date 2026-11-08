<?php
/** Render the real PHP template against narrow read-only doubles. */
define('ABSPATH',__DIR__.'/');
function add_action(...$args){}
function add_filter(...$args){}
function esc_html($s){return htmlspecialchars((string)$s,ENT_QUOTES,'UTF-8');}
function esc_attr($s){return esc_html($s);}
function esc_url($s){return esc_html($s);}
function __($s,...$args){return $s;}
function esc_html__($s,...$args){return esc_html($s);}
function esc_html_e($s,...$args){echo esc_html($s);}
function esc_attr__($s,...$args){return esc_attr($s);}
function esc_attr_e($s,...$args){echo esc_attr($s);}
function get_header(){}
function get_footer(){}
function have_posts(){static $calls=0;return $calls++===0;}
function the_post(){}
function post_class($s){echo 'class="'.esc_attr($s).'"';}
function get_the_ID(){return 1;}
function get_the_title(){return 'Tools';}
function home_url($s){return 'https://staging.cyberdat.eu'.$s;}
function get_page_by_path($s){return(object)['ID'=>1,'post_status'=>'publish'];}
function get_permalink($p){return 'https://staging.cyberdat.eu/tools/';}
function get_term_by(...$args){return false;}
class WP_Query {public $posts=[];function __construct($args){}}
function is_page($id){return true;}
function wp_parse_url($s,$part=-1){return parse_url($s,$part);}
function untrailingslashit($s){return rtrim($s,'/');}
require __DIR__.'/../wp-content/themes/cyberdat/inc/tools.php';
require __DIR__.'/../wp-content/themes/cyberdat/inc/navigation.php';
function check($ok,$label){if(!$ok)throw new RuntimeException($label);echo 'PASS: '.$label."\n";}
ob_start();require __DIR__.'/../wp-content/themes/cyberdat/page-templates/tools.php';$html=ob_get_clean();
check(substr_count($html,'data-tool-category=')===10,'ten actual template cards rendered without JavaScript');
check(substr_count($html,'class="tools-status">Coming Soon')===10,'all ten cards honestly marked Coming Soon');
check(str_contains($html,'CyberDat Security Tools')&&str_contains($html,'Free, privacy-focused utilities'),'heading and subtitle present');
preg_match_all('/<article class="cyberdat-tool-card tools-roadmap-card".*?<\/article>/s',$html,$cards);
foreach($cards[0] as $card){check(!str_contains($card,'<a '),'planned card is non-clickable');}
$road=json_decode(file_get_contents(__DIR__.'/../deploy/staging/tools-roadmap.json'),true);
$catalog=cyberdat_planned_tools();
check(array_column($catalog,'slug')===array_column($road,'slug'),'catalog matches all approved roadmap routes in order');
check(array_column($catalog,'phase')===array_column($road,'phase'),'release phases preserved');
$items='<li><a href="/">Home</a></li><li><a href="/topics/">Topics</a></li><li><a href="/news/">News</a></li><li><a href="/analysis/">Analysis</a></li><li><a href="/guides/">Guides</a></li><li><a href="/learning/">Learning</a></li>';
$args=(object)['theme_location'=>'primary'];$menu=cyberdat_tools_menu_item($items,$args);
check(str_starts_with($menu,$items)&&substr_count($menu,'<li')===7,'all six primary items preserved and Tools appended');
check(cyberdat_tools_menu_item($menu,$args)===$menu,'Tools is not duplicated');
check(cyberdat_tools_menu_item($items,(object)['theme_location'=>'footer'])===$items,'footer menu unchanged');
check(str_contains($menu,'aria-current="page"'),'Tools current page indicated');
check(str_contains($html,'data-tools-filters hidden'),'nonfunctional filters hidden until JS initializes');
echo 'PASS: catalog render and navigation suite' . "\n";
