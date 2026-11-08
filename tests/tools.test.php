<?php
/** Pure contract checks: no WordPress, real database or HTTP is loaded. */
define('ABSPATH', __DIR__ . '/');
$GLOBALS['hooks']=[]; $GLOBALS['posts']=[]; $GLOBALS['meta']=[];
$GLOBALS['renderer']=null; $GLOBALS['cap']=false; $GLOBALS['nonce']=false; $GLOBALS['saved']=0;
function add_action(...$a){}
function add_filter($name,$fn,...$a){$GLOBALS['hooks'][$name]=$fn;}
function apply_filters($name,$value,...$args){return 'cyberdat/tool/renderer'===$name ? $GLOBALS['renderer'] : $value;}
function get_page_template_slug($id){return $GLOBALS['posts'][$id]->template??'';}
function get_post($id){return $GLOBALS['posts'][$id]??null;}
function get_post_meta($id,$key,$single=true){return $GLOBALS['meta'][$id][$key]??[];}
function update_post_meta($id,$key,$value){$GLOBALS['saved']++;$GLOBALS['meta'][$id][$key]=$value;}
function sanitize_text_field($s){return trim(strip_tags($s));}
function wp_kses_post($s){return strip_tags($s,'<p><h3><strong><em><a><code><pre>');}
function wp_parse_url($s){return parse_url($s);}
function wp_strip_all_tags($s){return strip_tags($s);}
function current_user_can(...$a){return $GLOBALS['cap'];}
function wp_verify_nonce(...$a){return $GLOBALS['nonce'];}
function wp_unslash($s){return is_array($s)?array_map('wp_unslash',$s):stripslashes($s);}
function wp_is_post_revision($id){return false;}
function wp_is_post_autosave($id){return false;}
function is_singular($type){return $GLOBALS['singular']??false;}
function get_queried_object_id(){return 1;}
function get_post_status($id){return 'publish';}
function wp_get_environment_type(){return $GLOBALS['environment']??'local';}
function has_term(...$args){return $GLOBALS['news']??false;}
require __DIR__.'/../wp-content/themes/cyberdat/inc/tools.php';
function check($value,$message){if(!$value){throw new RuntimeException($message);}echo "PASS: $message\n";}
$GLOBALS['posts'][1]=(object)['ID'=>1,'template'=>'page-templates/tool.php','post_password'=>''];
$data=['reviewed'=>true,'summary'=>'Useful description','how_it_works'=>'Explanation','documentation'=>'Documentation','examples'=>'Examples','faq'=>'Questions'];
$GLOBALS['meta'][1]['_cyberdat_tool']=$data;
check(!cyberdat_tool_ready(1),'reviewed metadata alone cannot release a fake tool');
$GLOBALS['renderer']=static function(){};
check(cyberdat_tool_ready(1),'reviewed implemented tool with all content can be ready');
foreach(['summary','how_it_works','documentation','examples','faq'] as $key){$GLOBALS['meta'][1]['_cyberdat_tool'][$key]='';check(!cyberdat_tool_ready(1),"missing $key blocks readiness");$GLOBALS['meta'][1]['_cyberdat_tool']=$data;}
$GLOBALS['posts'][1]->post_password='test';check(!cyberdat_tool_ready(1),'password-protected tool excluded');$GLOBALS['posts'][1]->post_password='';
foreach(['javascript:alert(1)','https://github.com.evil.test/x','https://user:pass@github.com/a/b','http://github.com/a/b'] as $url){check(''===cyberdat_tool_sanitize(['github'=>$url])['github'],'unsafe GitHub URL removed');}
check('https://github.com/CyberDat/CyberDat-AI'===cyberdat_tool_sanitize(['github'=>'https://github.com/CyberDat/CyberDat-AI'])['github'],'published GitHub HTTPS URL allowed');
check(!str_contains(cyberdat_tool_sanitize(['documentation'=>'<script>bad()</script><strong>safe</strong>'])['documentation'],'<script>'),'editorial HTML sanitized');
$_POST=['cyberdat_tool_nonce'=>'test','cyberdat_tool'=>$data];
cyberdat_tool_save(1);check(0===$GLOBALS['saved'],'save rejects missing capability and nonce');
$GLOBALS['nonce']=true;cyberdat_tool_save(1);check(0===$GLOBALS['saved'],'valid nonce cannot replace capability');
$GLOBALS['cap']=true;cyberdat_tool_save(1);check(1===$GLOBALS['saved'],'authorized nonced save succeeds');
$GLOBALS['renderer']=null;
foreach(['publish','future'] as $status){$out=cyberdat_tool_publication_guard(['post_type'=>'page','post_status'=>$status],['ID'=>1]);check('draft'===$out['post_status'],"$status fails closed");}
$out=cyberdat_tool_publication_guard(['post_type'=>'post','post_status'=>'publish'],['ID'=>2]);check('publish'===$out['post_status'],'normal editorial posts unaffected');
$entry=$GLOBALS['hooks']['rank_math/sitemap/entry'];check(false===$entry(['loc'=>'test'],'post',(object)['ID'=>1]),'unfinished tool excluded from Rank Math sitemap');
$GLOBALS['singular']=true;
$robots=($GLOBALS['hooks']['rank_math/frontend/robots'])(['index'=>'index','follow'=>'nofollow']);check('noindex'===$robots['index']&&'nofollow'===$robots['follow'],'noindex added without weakening nofollow');
$GLOBALS['environment']='staging';$GLOBALS['singular']=false;
$robots=($GLOBALS['hooks']['rank_math/frontend/robots'])(['index'=>'index','follow'=>'follow']);check('noindex'===$robots['index']&&'nofollow'===$robots['follow'],'Rank Math cannot weaken staging robots');
$GLOBALS['singular']=true;
$schema=$GLOBALS['hooks']['rank_math/snippet/rich_snippet_article_entity'];
$article=['@type'=>'Article','headline'=>'Real title','datePublished'=>'2026-11-08','author'=>['name'=>'Author']];
$GLOBALS['news']=true;check('NewsArticle'===$schema($article)['@type'],'existing news Article entity refined through Rank Math');
$GLOBALS['meta'][1]['_cyberdat_staging_fixture']=1;check('Article'===$schema($article)['@type'],'sample fixture is not promoted to NewsArticle');
check(!str_contains(file_get_contents(__DIR__.'/../wp-content/themes/cyberdat/inc/tools.php'),'application/ld+json'),'theme does not emit a second JSON-LD graph');
echo "PASS: tools contract suite\n";
