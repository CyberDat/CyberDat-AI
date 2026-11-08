<?php
/** Run only via staging WP-CLI; native drafts, never dummy functional tools. */
if ( ! defined('WP_CLI') || ! WP_CLI || 'staging' !== wp_get_environment_type() || '/var/www/cyberdat-staging/public/' !== ABSPATH || 'https://staging.cyberdat.eu' !== get_option('home') || 'cyberdat_staging' !== DB_NAME ) {
    throw new RuntimeException('Staging identity mismatch');
}
$roadmap = json_decode(file_get_contents($args[0]), true, 512, JSON_THROW_ON_ERROR);
$hub = get_page_by_path('tools');
if ($hub && !get_post_meta($hub->ID, '_cyberdat_tools_architecture', true)) {
    throw new RuntimeException('Existing unowned Tools page; review required');
}
foreach ($roadmap as $tool) {
    $existing = get_page_by_path('tools/'.$tool['slug']);
    if ($existing && !get_post_meta($existing->ID, '_cyberdat_tools_architecture', true)) {
        throw new RuntimeException('Existing unowned tool route; review required');
    }
    $root_collision = get_page_by_path($tool['slug']);
    if ($root_collision) { throw new RuntimeException('Unrelated top-level slug collision'); }
}
if (!$hub) {
    $id = wp_insert_post([
        'post_type'=>'page', 'post_status'=>'publish', 'post_title'=>'Tools', 'post_name'=>'tools',
        'post_content'=>'<!-- wp:paragraph --><p>CyberDat tools are being developed with an emphasis on technical accuracy and privacy. Released utilities will appear here after implementation and review. Explore our guides, learning resources and analysis in the meantime.</p><!-- /wp:paragraph -->',
        'meta_input'=>['_wp_page_template'=>'page-templates/tools.php','_cyberdat_tools_architecture'=>'0.7'],
    ], true);
    if (is_wp_error($id)) { throw new RuntimeException('Tools hub creation failed'); }
    $hub = get_post($id);
}
$ids=[];
foreach ($roadmap as $tool) {
    $page=get_page_by_path('tools/'.$tool['slug']);
    if (!$page) {
        $id=wp_insert_post([
            'post_type'=>'page','post_status'=>'draft','post_title'=>$tool['title'],
            'post_name'=>$tool['slug'],'post_parent'=>$hub->ID,'post_content'=>'',
            'meta_input'=>['_wp_page_template'=>'page-templates/tool.php','_cyberdat_tools_architecture'=>'0.7',
                '_cyberdat_tool'=>['reviewed'=>false],
                'rank_math_title'=>$tool['title'].' | CyberDat',
                'rank_math_description'=>$tool['title'].' — planned CyberDat utility; not released. Editorial draft only.'],
        ],true);
        if (is_wp_error($id)) { throw new RuntimeException('Tool draft creation failed'); }
        $page=get_post($id);
    }
    if ('draft'!==$page->post_status || cyberdat_tool_ready($page->ID)) {throw new RuntimeException('Unexpected tool release state');}
    $ids[]=$page->ID;
}
update_option('rank_math_modules', ['sitemap','rich-snippet']);
$general=get_option('rank-math-options-general',[]);
$general['breadcrumbs']=true;
update_option('rank-math-options-general',$general);
flush_rewrite_rules(false);
echo wp_json_encode(['hub'=>$hub->ID,'drafts'=>$ids,'ready_tools'=>count(cyberdat_ready_tools())]);
