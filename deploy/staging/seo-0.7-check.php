<?php
/** Consolidated real-WordPress integration contracts; no fixture writes. */
if (!defined('WP_CLI') || !WP_CLI || 'staging'!==wp_get_environment_type() || 'cyberdat_staging'!==DB_NAME || '/var/www/cyberdat-staging/public/'!==ABSPATH) {throw new RuntimeException('Wrong environment');}
function cd_seo_check($value,$label){if(!$value){throw new RuntimeException($label);}echo 'PASS: '.$label."\n";}
cd_seo_check('0'===(string)get_option('blog_public'),'staging indexing remains disabled');
cd_seo_check(defined('CYBERDAT_KEV_LIVE')&&!CYBERDAT_KEV_LIVE&&defined('CYBERDAT_NVD_LIVE')&&!CYBERDAT_NVD_LIVE,'live KEV/NVD remain disabled');
cd_seo_check(defined('DISABLE_WP_CRON')&&DISABLE_WP_CRON&&defined('AUTOMATIC_UPDATER_DISABLED')&&AUTOMATIC_UPDATER_DISABLED,'Cron and automatic updates remain guarded');
cd_seo_check(is_wp_error(wp_remote_get('https://example.org', ['timeout'=>1])),'outbound WordPress HTTP blocked');
cd_seo_check(false===apply_filters('pre_wp_mail',null,[]),'outgoing email blocked without sending');
cd_seo_check(in_array('seo-by-rank-math/rank-math.php',(array)get_option('active_plugins'),true),'Rank Math active');
cd_seo_check('cyberdat'===get_stylesheet(),'CyberDat active');
cd_seo_check('/%postname%/'===get_option('permalink_structure'),'post URLs unchanged');
$hub=get_page_by_path('tools');
cd_seo_check($hub&&'publish'===$hub->post_status&&cyberdat_tools_excluded($hub->ID),'empty tools hub excluded from index and sitemap');
$roadmap=json_decode(file_get_contents($args[0]),true,512,JSON_THROW_ON_ERROR);
foreach($roadmap as $tool){
 $page=get_page_by_path('tools/'.$tool['slug']);
 cd_seo_check($page&&'draft'===$page->post_status&&!cyberdat_tool_ready($page->ID),'planned draft '.$tool['slug']);
 cd_seo_check(false===apply_filters('rank_math/sitemap/entry',['loc'=>'test'],'post',$page),'sitemap exclusion '.$tool['slug']);
 $data=cyberdat_tool_publication_guard(['post_type'=>'page','post_status'=>'publish'],['ID'=>$page->ID]);
 cd_seo_check('draft'===$data['post_status'],'publication guard '.$tool['slug']);
}
$meta=get_registered_meta_keys('post','page');
cd_seo_check(isset($meta['_cyberdat_tool']['show_in_rest']['schema']['properties']['reviewed']),'typed REST metadata available');
cd_seo_check(taxonomy_exists('editorial_format')&&get_taxonomy('editorial_format')->show_in_rest,'existing taxonomy REST API preserved');
$robots=apply_filters('rank_math/frontend/robots',['index'=>'index','follow'=>'follow']);
cd_seo_check('noindex'===$robots['index']&&'nofollow'===$robots['follow'],'Rank Math staging noindex/nofollow enforced');
cd_seo_check(0===count(cyberdat_ready_tools()),'no fictional working tools');
cd_seo_check(!wp_get_sitemap_providers(),'core sitemap disabled while Rank Math owns sitemap');
echo 'PASS: real WordPress SEO integration contracts' . "\n";
