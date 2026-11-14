<?php
/** Render the real PHP template against narrow read-only doubles. */
define('ABSPATH',__DIR__.'/');
function add_action(...$args){}
function wp_enqueue_style(...$args){}
function get_theme_file_uri($s){return '/wp-content/themes/cyberdat'.$s;}
function get_theme_file_path($s){return __DIR__.'/../wp-content/themes/cyberdat'.$s;}
function cyberdat_theme_asset_version($s){return 'fixture';}
function add_filter(...$args){}
function esc_html($s){return htmlspecialchars((string)$s,ENT_QUOTES,'UTF-8');}
function esc_attr($s){return esc_html($s);}
function esc_url($s){return esc_html($s);}
function __($s,...$args){return $s;}
function esc_html__($s,...$args){return esc_html($s);}
function esc_html_e($s,...$args){echo esc_html($s);}
function esc_attr__($s,...$args){return esc_attr($s);}
function esc_attr_e($s,...$args){echo esc_attr($s);}
function get_header(){if(in_array('--html',$GLOBALS['argv']??[],true)){echo '<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">';foreach(['tokens','main','tools'] as $css)echo '<link rel="stylesheet" href="/wp-content/themes/cyberdat/assets/css/'.$css.'.css">';echo '</head><body><main class="site-main"><div class="container">';}}
function get_footer(){if(in_array('--html',$GLOBALS['argv']??[],true))echo '</div></main><script src="/wp-content/themes/cyberdat/assets/js/tools-filter.js"></script></body></html>';}
$GLOBALS['loop']=0;function have_posts(){return $GLOBALS['loop']++===0;}
function the_post(){}
function post_class($s){echo 'class="'.esc_attr($s).'"';}
function get_the_ID(){return 1;}
function get_the_title(){return 'Tools';}
function home_url($s){return 'https://staging.cyberdat.eu'.$s;}
function get_page_by_path($s){return(object)['ID'=>1,'post_status'=>'publish'];}
function get_permalink($p){return is_object($p)&&isset($p->post_name)?'https://staging.cyberdat.eu/tools/'.$p->post_name.'/':'https://staging.cyberdat.eu/tools/';}
function get_term_by(...$args){return false;}
class WP_Query {public $posts=[];function __construct($args){$this->posts=$GLOBALS['ready_posts']??[];}}
// Readiness doubles: a published Log Anonymizer page with reviewed content and a registered renderer.
$GLOBALS['tool_post']=(object)['ID'=>5,'post_name'=>'log-anonymizer','post_password'=>''];
$GLOBALS['pi_post']=(object)['ID'=>6,'post_name'=>'prompt-injection-detector','post_password'=>''];
$GLOBALS['lotl_post']=(object)['ID'=>7,'post_name'=>'lotl-command-analyzer','post_password'=>''];
$GLOBALS['mcp_post']=(object)['ID'=>8,'post_name'=>'mcp-security-checker','post_password'=>''];
function get_post($id){return [5=>$GLOBALS['tool_post'],6=>$GLOBALS['pi_post'],7=>$GLOBALS['lotl_post'],8=>$GLOBALS['mcp_post']][$id]??null;}
function get_page_template_slug($id){return in_array($id,[5,6,7,8],true)?'page-templates/tool.php':'page-templates/tools.php';}
function apply_filters($hook,$value,...$args){return 'cyberdat/tool/renderer'===$hook&&in_array($args[0]??0,[5,6,7,8],true)?'strlen':$value;}
function get_post_meta(...$a){return ['reviewed'=>true,'summary'=>'s','how_it_works'=>'h','documentation'=>'d','examples'=>'e','faq'=>'f'];}
function wp_strip_all_tags($s){return strip_tags($s);}
function sanitize_text_field($s){return trim(strip_tags($s));}
function wp_kses_post($s){return $s;}
function is_page($id){return true;}
function wp_parse_url($s,$part=-1){return parse_url($s,$part);}
function untrailingslashit($s){return rtrim($s,'/');}
require __DIR__.'/../wp-content/themes/cyberdat/inc/tools.php';
require __DIR__.'/../wp-content/themes/cyberdat/inc/navigation.php';
function check($ok,$label){if(!$ok)throw new RuntimeException($label);echo 'PASS: '.$label."\n";}
function render(){$GLOBALS['loop']=0;ob_start();require __DIR__.'/../wp-content/themes/cyberdat/page-templates/tools.php';return ob_get_clean();}
$html=render();
if(in_array('--html',$argv??[],true)){echo $html;exit;}
$catalog=cyberdat_planned_tools();
check(count($catalog)===10,'full ten-tool catalogue retained');
preg_match_all('/<article class="cyberdat-tool-card tools-roadmap-card[^"]*".*?<\/article>/s',$html,$cards);
check(count($cards[0])===10,'all ten cards server-rendered without JavaScript');
foreach($catalog as $tool){check(str_contains($html,esc_html($tool['title'])),'card retained: '.$tool['slug']);}
check(str_contains($html,'data-tools-filters hidden')&&str_contains($html,'data-tools-count'),'progressive-enhancement filter controls and live count restored');
check(substr_count($html,'data-tools-filter=')===6,'All and five category buttons');
check(str_contains($html,'10 / 10 tools shown'),'initial counter reflects all ten cards');
check(substr_count($html,'class="tools-status">Coming soon')===10,'unpublished cards honestly remain Coming soon');
foreach($cards[0] as $card){check(!str_contains($card,'<a '),'unavailable card stays non-clickable');}
foreach([1,2,3,4] as $count){
 $GLOBALS['ready_posts']=array_slice([$GLOBALS['tool_post'],$GLOBALS['pi_post'],$GLOBALS['lotl_post'],$GLOBALS['mcp_post']],0,$count);
 $rendered=render();
 check(substr_count($rendered,'data-tool-category=')===10,'readiness never hides other catalogue cards');
 check(substr_count($rendered,'class="tools-status">Available')===$count,'only ready tools advertise availability');
 check(substr_count($rendered,'class="tools-status">Coming soon')===10-$count,'remaining cards stay non-clickable planned entries');
}
check(str_contains($rendered,'href="https://staging.cyberdat.eu/tools/mcp-security-checker/"'),'MCP readiness and canonical link preserved');
$road=json_decode(file_get_contents(__DIR__.'/../deploy/tools-release-1/route-catalog.json'),true);
check(array_column($catalog,'slug')===array_column($road,'slug'),'catalogue order unchanged');
check(array_count_values(array_column($catalog,'release'))===['1.1'=>3,'1.2'=>4,'1.3'=>3],'original release split unchanged');
check(count(array_filter($catalog,static fn($t)=>$t['status']==='available'))===4,'all four implementation entries retained');
$items='<li><a href="/">Home</a></li><li><a href="/topics/">Topics</a></li><li><a href="/news/">News</a></li><li><a href="/analysis/">Analysis</a></li><li><a href="/guides/">Guides</a></li><li><a href="/learning/">Learning</a></li>';
$args=(object)['theme_location'=>'primary'];$menu=cyberdat_tools_menu_item($items,$args);
check(str_starts_with($menu,$items)&&substr_count($menu,'<li')===7,'all six primary items preserved and Tools appended');
check(cyberdat_tools_menu_item($menu,$args)===$menu,'Tools is not duplicated');
check(cyberdat_tools_menu_item($items,(object)['theme_location'=>'footer'])===$items,'footer menu unchanged');
check(str_contains($menu,'aria-current="page"'),'Tools current page indicated');
echo 'PASS: catalog render and navigation suite' . "\n";
