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
function get_post($id){return 5===$id?$GLOBALS['tool_post']:(6===$id?$GLOBALS['pi_post']:null);}
function get_page_template_slug($id){return in_array($id,[5,6],true)?'page-templates/tool.php':'page-templates/tools.php';}
function apply_filters($hook,$value,...$args){return 'cyberdat/tool/renderer'===$hook&&in_array($args[0]??0,[5,6],true)?'strlen':$value;}
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
preg_match_all('/<article class="cyberdat-tool-card tools-roadmap-card[^"]*".*?<\/article>/s',$html,$cards);
check(count($cards[0])===3,'exactly the three release 1.1 tools rendered without JavaScript');
foreach(['Privacy Shield Log Anonymizer','Indirect Prompt Injection Sanitizer &amp; Detector','LotL / LOLBAS Command Analyzer'] as $title){check(str_contains($html,$title),"release 1.1 card: $title");}
foreach(['IoT','Modbus','Webhook','MCP Security','ATLAS','YARA'] as $gone){check(!str_contains($html,$gone),"no card for $gone");}
check(substr_count($html,'class="tools-status">Coming soon')===3,'while no tool page is ready, all three honestly say Coming soon');
foreach($cards[0] as $card){check(!str_contains($card,'<a '),'unavailable card is non-clickable');}
check(substr_count($html,'More tools planned.')===1,'one "More tools planned" line instead of empty roadmap cards');
check(str_contains($html,'No tool is available yet'),'notice does not claim availability before readiness');
check(!str_contains($html,'data-tools-filters'),'no category filters for three cards');
check(str_contains($html,'CyberDat Security Tools')&&str_contains($html,'Free, privacy-focused utilities'),'heading and subtitle present');
$GLOBALS['ready_posts']=[$GLOBALS['tool_post']];
$html=render();
preg_match_all('/<article class="cyberdat-tool-card tools-roadmap-card[^"]*".*?<\/article>/s',$html,$cards);
check(str_contains($cards[0][0],'class="tools-status">Available')&&str_contains($cards[0][0],'href="https://staging.cyberdat.eu/tools/log-anonymizer/"'),'ready Log Anonymizer page: card says Available and links to the tool');
check(substr_count($html,'class="tools-status">Coming soon')===2&&!str_contains($cards[0][1].$cards[0][2],'<a '),'other two stay Coming soon and non-clickable');
check(str_contains($html,'the text you enter is never sent anywhere'),'privacy notice uses the approved wording');
$GLOBALS['ready_posts']=[$GLOBALS['tool_post'],$GLOBALS['pi_post']];
$html=render();
preg_match_all('/<article class="cyberdat-tool-card tools-roadmap-card[^"]*".*?<\/article>/s',$html,$cards);
check(str_contains($cards[0][1],'class="tools-status">Available')&&str_contains($cards[0][1],'href="https://staging.cyberdat.eu/tools/prompt-injection-detector/"'),'ready Prompt Injection Detector page: card says Available and links to /tools/prompt-injection-detector/');
check(substr_count($html,'class="tools-status">Available')===2&&substr_count($html,'class="tools-status">Coming soon')===1&&!str_contains($cards[0][2],'<a '),'two tools available, LOLBAS Analyzer stays Coming soon and non-clickable');
check(str_contains($html,'Indirect Prompt Injection Sanitizer &amp; Detector'),'tool name unchanged');
$road=json_decode(file_get_contents(__DIR__.'/../deploy/staging/tools-roadmap.json'),true);
$catalog=cyberdat_planned_tools();
check(count($catalog)===10&&array_column($catalog,'slug')===array_column($road,'slug'),'catalogue keeps the ten approved tools (TZ v1.0) and matches the roadmap in order');
check(array_column($catalog,'release')===array_column($road,'release')&&array_count_values(array_column($catalog,'release'))===['1.1'=>3,'1.2'=>4,'1.3'=>3],'release split 3/4/3 as approved');
check(!array_intersect(array_column($catalog,'slug'),['iot-exposure-query-builder','modbus-decoder','webhook-oob-listener']),'backlog tools removed from the catalogue');
$items='<li><a href="/">Home</a></li><li><a href="/topics/">Topics</a></li><li><a href="/news/">News</a></li><li><a href="/analysis/">Analysis</a></li><li><a href="/guides/">Guides</a></li><li><a href="/learning/">Learning</a></li>';
$args=(object)['theme_location'=>'primary'];$menu=cyberdat_tools_menu_item($items,$args);
check(str_starts_with($menu,$items)&&substr_count($menu,'<li')===7,'all six primary items preserved and Tools appended');
check(cyberdat_tools_menu_item($menu,$args)===$menu,'Tools is not duplicated');
check(cyberdat_tools_menu_item($items,(object)['theme_location'=>'footer'])===$items,'footer menu unchanged');
check(str_contains($menu,'aria-current="page"'),'Tools current page indicated');
echo 'PASS: catalog render and navigation suite' . "\n";
