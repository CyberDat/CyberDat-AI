<?php
defined('ABSPATH') || exit;
function cyberdat_intelligence_url(){return home_url('/threat-intelligence/');}
function cyberdat_is_intelligence_page(){return is_page('threat-intelligence')&&is_page_template('page-templates/threat-intelligence.php')&&cyberdat_home_preview_allowed();}
function cyberdat_intelligence_menu($items,$args){
 if(($args->theme_location??'')!=='primary'||!cyberdat_home_preview_allowed()){return $items;}
 $page=get_page_by_path('threat-intelligence');if(!$page||$page->post_status!=='publish'){return $items;}$url=cyberdat_intelligence_url();
 preg_match_all('/href=[\x22\x27]([^\x22\x27]+)[\x22\x27]/',$items,$links);
 foreach($links[1] as $link){$link=html_entity_decode($link,ENT_QUOTES,'UTF-8');if(untrailingslashit($link)===untrailingslashit($url)||untrailingslashit($link)==='/threat-intelligence'){return $items;}}
 return $items.'<li class="menu-item"><a href="'.esc_url($url).'"'.(is_page($page->ID)?' aria-current="page"':'').'>'.esc_html__('Threat Intelligence','cyberdat').'</a></li>';
}
add_filter('wp_nav_menu_items','cyberdat_intelligence_menu',20,2);
