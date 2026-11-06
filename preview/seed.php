<?php
/** Deterministic demonstration data inside browser-only WordPress. */
require '/wordpress/wp-load.php';
if (!defined('CYBERDAT_PLAYGROUND') || !CYBERDAT_PLAYGROUND) { throw new RuntimeException('Playground guard is missing.'); }
function cyberdat_preview_result($result) {
    if (is_wp_error($result)) { throw new RuntimeException($result->get_error_message()); }
    return $result;
}
wp_set_current_user(1);
update_option('blogname','CyberDat');
update_option('blogdescription','Cybersecurity News, Analysis & Learning');
update_option('blog_public',0);
update_option('posts_per_page',6);
$GLOBALS['wp_rewrite']->set_category_base('topics');
update_option('show_on_front','posts');
$GLOBALS['wp_rewrite']->set_permalink_structure('/%postname%/');
$topics=[
 'cybersecurity-fundamentals'=>'Cybersecurity Fundamentals', 'ai-security'=>'AI Security',
 'network-security'=>'Network Security', 'ethical-hacking'=>'Ethical Hacking',
 'threat-intelligence'=>'Threat Intelligence'
];
$topic_ids=[];
foreach($topics as $slug=>$name){
 $term=get_term_by('slug',$slug,'category');
 $topic_ids[$slug]=$term ? $term->term_id : cyberdat_preview_result(wp_insert_term($name,'category',['slug'=>$slug]))['term_id'];
}
$format_ids=[];
foreach(['news'=>'News','analysis'=>'Analysis','guides'=>'Guides','learning'=>'Learning'] as $slug=>$name){
 $term=get_term_by('slug',$slug,'editorial_format');
 $format_ids[$slug]=$term ? $term->term_id : cyberdat_preview_result(wp_insert_term($name,'editorial_format',['slug'=>$slug]))['term_id'];
}
// Remove only the stock fixtures in this new, isolated Playground instance.
foreach(['Hello world!','Sample Page'] as $title){
 $items=get_posts(['post_type'=>['post','page'],'post_status'=>'any','title'=>$title,'numberposts'=>-1]);
 foreach($items as $item){wp_delete_post($item->ID,true);}
}
function cyberdat_preview_post($slug,$title,$type,$content,$extra=[]) {
    $existing=get_page_by_path($slug,OBJECT,$type);
    if($existing){ return $existing->ID; }
    return cyberdat_preview_result(wp_insert_post(array_merge([
        'post_type'=>$type, 'post_status'=>'publish', 'post_name'=>$slug,
        'post_title'=>$title, 'post_content'=>$content, 'post_author'=>1,
        'post_date'=>'2026-11-01 10:00:00', 'post_date_gmt'=>'2026-11-01 10:00:00',
        'comment_status'=>'closed', 'ping_status'=>'closed'
    ],$extra),true));
}
$body=<<<'HTML'
<!-- wp:paragraph --><p><strong>Playground demonstration.</strong> This fictional fixture exists only to inspect the CyberDat theme. It is not a published CyberDat report or security advisory.</p><!-- /wp:paragraph -->
<!-- wp:heading --><h2 class="wp-block-heading">What this preview checks</h2><!-- /wp:heading -->
<!-- wp:paragraph --><p>Readable typography, clear navigation and a consistent dark palette are the foundation of an editorial cybersecurity publication. The final portal and threat-analysis dashboard will be developed in later stages.</p><!-- /wp:paragraph -->
<!-- wp:heading {"level":3} --><h3 class="wp-block-heading">A practical reading experience</h3><!-- /wp:heading -->
<!-- wp:paragraph --><p>Headings, links, lists and long technical identifiers should remain usable on a narrow screen. Explore the <a href="/block-showcase/">Gutenberg block showcase</a> to inspect richer content.</p><!-- /wp:paragraph -->
<!-- wp:list --><ul class="wp-block-list"><!-- wp:list-item --><li>Check the mobile navigation with the keyboard.</li><!-- /wp:list-item --><!-- wp:list-item --><li>Read the article at 320, 768 and 1440 pixels.</li><!-- /wp:list-item --><!-- wp:list-item --><li>Inspect the topic and editorial-format archives.</li><!-- /wp:list-item --></ul><!-- /wp:list -->
HTML;
$articles=[
 ['identity-boundaries-for-ai-agents','Identity boundaries for AI agents','ai-security','analysis'],
 ['network-segmentation-checklist','A practical network segmentation checklist','network-security','guides'],
 ['understanding-threat-intelligence','Understanding threat intelligence: from signals to context','threat-intelligence','learning'],
 ['preview-security-briefing','Security briefing: a fictional preview edition','threat-intelligence','news'],
 ['cybersecurity-foundations','Cybersecurity foundations: understanding risk and trust','cybersecurity-fundamentals','learning'],
 ['ethical-hacking-scope','Defining scope for an authorized security assessment','ethical-hacking','guides'],
 ['ai-security-review','A security review of AI-assisted workflows and their trust boundaries','ai-security','analysis'],
 ['network-defense-preview','Network defense notes: demonstration update','network-security','news']
];
foreach($articles as $i=>$a){
 $id=cyberdat_preview_post($a[0],$a[1],'post',$body,['post_excerpt'=>'Demonstration content for layout review. Inspect the hierarchy, card spacing and reading experience across screen sizes.','post_date'=>sprintf('2026-10-%02d 10:00:00',$i+20),'post_date_gmt'=>sprintf('2026-10-%02d 10:00:00',$i+20)]);
 cyberdat_preview_result(wp_set_post_terms($id,[$topic_ids[$a[2]]],'category'));
 cyberdat_preview_result(wp_set_post_terms($id,[$format_ids[$a[3]]],'editorial_format'));
}
$topic_content='<!-- wp:paragraph --><p>Demonstration topic directory. Select a topic to inspect the archive template.</p><!-- /wp:paragraph --><!-- wp:list --><ul class="wp-block-list">';
foreach($topic_ids as $slug=>$id){$topic_content.='<!-- wp:list-item --><li><a href="'.esc_url(get_term_link($id,'category')).'">'.esc_html($topics[$slug]).'</a></li><!-- /wp:list-item -->';}
$topic_content.='</ul><!-- /wp:list -->';
cyberdat_preview_post('topics','Topics','page',$topic_content);
cyberdat_preview_post('about-preview','About this preview','page','<!-- wp:paragraph --><p>This is an isolated browser-only demonstration of CyberDat 0.1.0. No production database, passwords or services are connected.</p><!-- /wp:paragraph -->');
$blocks=<<<'HTML'
<!-- wp:paragraph --><p>This page exercises core Gutenberg blocks. Open it in the editor to compare the editing canvas with the frontend.</p><!-- /wp:paragraph -->
<!-- wp:heading --><h2 class="wp-block-heading">Headings, links and paragraphs</h2><!-- /wp:heading -->
<!-- wp:paragraph --><p>A readable paragraph with <strong>strong emphasis</strong>, <em>italic text</em> and an <a href="/topics/">internal topic link</a>. This is a fixture, not production content.</p><!-- /wp:paragraph -->
<!-- wp:heading {"level":3} --><h3 class="wp-block-heading">Long identifiers and code</h3><!-- /wp:heading -->
<!-- wp:code --><pre class="wp-block-code"><code>GET /example/security/events?source=demonstration&amp;correlation_id=preview_identifier_with_a_deliberately_long_value_for_horizontal_scroll_testing</code></pre><!-- /wp:code -->
<!-- wp:quote --><blockquote class="wp-block-quote"><!-- wp:paragraph --><p>Clear context matters more than decorative complexity.</p><!-- /wp:paragraph --><cite>CyberDat preview fixture</cite></blockquote><!-- /wp:quote -->
<!-- wp:table --><figure class="wp-block-table"><table class="has-fixed-layout"><thead><tr><th>Component</th><th>Review</th></tr></thead><tbody><tr><td>Navigation</td><td>Keyboard and mobile disclosure</td></tr><tr><td>Typography</td><td>Long titles and readable paragraphs</td></tr></tbody></table></figure><!-- /wp:table -->
<!-- wp:columns --><div class="wp-block-columns"><!-- wp:column --><div class="wp-block-column"><!-- wp:heading {"level":3} --><h3 class="wp-block-heading">Analysis</h3><!-- /wp:heading --><!-- wp:paragraph --><p>Inspect column stacking on small screens.</p><!-- /wp:paragraph --></div><!-- /wp:column --><!-- wp:column --><div class="wp-block-column"><!-- wp:heading {"level":3} --><h3 class="wp-block-heading">Learning</h3><!-- /wp:heading --><!-- wp:paragraph --><p>Inspect spacing and alignment in the editor.</p><!-- /wp:paragraph --></div><!-- /wp:column --></div><!-- /wp:columns -->
<!-- wp:buttons --><div class="wp-block-buttons"><!-- wp:button --><div class="wp-block-button"><a class="wp-block-button__link wp-element-button" href="/guides/">Explore guides</a></div><!-- /wp:button --></div><!-- /wp:buttons -->
<!-- wp:group {"backgroundColor":"surface","layout":{"type":"constrained"}} --><div class="wp-block-group has-surface-background-color has-background"><!-- wp:paragraph --><p>A grouped block using the theme palette.</p><!-- /wp:paragraph --></div><!-- /wp:group -->
HTML;
cyberdat_preview_post('block-showcase','Gutenberg Block Showcase','page',$blocks);
// Preview-specific test links must retain Playground's generated scope prefix.
foreach(get_posts(['post_type'=>['post','page'],'numberposts'=>-1]) as $post){
 $content=preg_replace_callback('~href="/(block-showcase|topics|guides)/"~',function($m){return 'href="'.esc_url(home_url('/'.$m[1].'/')).'"';},$post->post_content);
 if($content!==$post->post_content){wp_update_post(['ID'=>$post->ID,'post_content'=>$content]);}
}
$footer=wp_get_nav_menu_object('Preview Footer');
$footer_id=$footer ? $footer->term_id : cyberdat_preview_result(wp_create_nav_menu('Preview Footer'));
if(!wp_get_nav_menu_items($footer_id)){
 foreach(['block-showcase'=>'Block Showcase','about-preview'=>'About this preview'] as $slug=>$label){
  $page=get_page_by_path($slug);
  cyberdat_preview_result(wp_update_nav_menu_item($footer_id,0,['menu-item-title'=>$label,'menu-item-object-id'=>$page->ID,'menu-item-object'=>'page','menu-item-type'=>'post_type','menu-item-status'=>'publish']));
 }
}
set_theme_mod('nav_menu_locations',['footer'=>$footer_id]);
flush_rewrite_rules(false);
if(get_option('stylesheet')!=='cyberdat'){throw new RuntimeException('CyberDat theme was not activated in Playground.');}
if((int)get_option('blog_public')!==0){throw new RuntimeException('Preview indexing is not disabled.');}
if(count(get_posts(['post_type'=>'post','numberposts'=>-1]))!==8){throw new RuntimeException('Unexpected preview article count.');}
foreach($format_ids as $slug=>$id){if(is_wp_error(get_term_link($id,'editorial_format'))){throw new RuntimeException('Format link failed.');}}
echo "CyberDat fixtures ready: 8 articles, 3 pages, 5 topics, 4 editorial formats.\n";
