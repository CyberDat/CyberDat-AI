<?php
/** Real WP_Query and rendering tests; disposable browser-only database. */
require '/wordpress/wp-load.php';
if (!defined('CYBERDAT_PLAYGROUND') || !CYBERDAT_PLAYGROUND || ABSPATH !== '/wordpress/') { throw new RuntimeException('Playground-only test guard failed'); }
$results=[];$created=[];$fixtures=get_posts(['post_type'=>'post','post_status'=>'publish','numberposts'=>-1]);
$before_user=get_current_user_id();$before_post=$_POST;
function cds_check($label,$passed){global $results;$results[]=['test'=>$label,'status'=>$passed?'PASS':'FAIL'];if(!$passed){throw new RuntimeException($label);}}
function cds_snapshot($posts){
 $data=[];foreach($posts as $p){$p=get_post($p->ID);$data[$p->ID]=[$p->post_status,$p->post_date,$p->post_date_gmt,$p->post_title,$p->post_content,$p->post_excerpt,wp_get_post_terms($p->ID,'category',['fields'=>'ids']),wp_get_post_terms($p->ID,'editorial_format',['fields'=>'ids']),get_post_meta($p->ID)];}return $data;
}
function cds_fixture($date,$formats=['analysis'],$topics=['ai-security'],$extra=[]){
 global $created;
 $id=wp_insert_post(array_merge(['post_type'=>'post','post_status'=>'publish','post_title'=>'Section fixture','post_content'=>'Isolated test content.','post_excerpt'=>'Isolated section excerpt.','post_author'=>1,'post_date'=>$date,'post_date_gmt'=>$date,'comment_status'=>'closed'],$extra),true);
 if(is_wp_error($id)){throw new RuntimeException($id->get_error_message());}$created[]=$id;
 foreach(['editorial_format'=>$formats,'category'=>$topics] as $taxonomy=>$slugs){$ids=[];foreach($slugs as $slug){$term=get_term_by('slug',$slug,$taxonomy);if(!$term){throw new RuntimeException('Missing existing fixture term');}$ids[]=$term->term_id;}$saved=wp_set_post_terms($id,$ids,$taxonomy);if(is_wp_error($saved)){throw new RuntimeException($saved->get_error_message());}}
 return $id;
}
function cds_ids($taxonomy,$terms,$featured=0){return array_map('intval',wp_list_pluck(cyberdat_section_posts($taxonomy,$terms,$featured),'ID'));}
function cds_render($taxonomy='editorial_format',$terms=['analysis']){ob_start();cyberdat_editorial_section('Latest Analysis','BEYOND THE HEADLINE',$taxonomy,$terms,'/analysis/','analysis');return ob_get_clean();}
$snapshot=cds_snapshot($fixtures);
try{
 wp_set_current_user(1);$_POST=[];
 foreach($fixtures as $p){wp_update_post(['ID'=>$p->ID,'post_status'=>'draft']);}
 cds_check('Empty queries contain no invented posts',cds_ids('editorial_format',['analysis'])===[] && cds_ids('category',['ai-security'])===[] && cds_ids('editorial_format',['guides','learning'])===[]);
 $html=cds_render();cds_check('Playground empty state contains no article links',str_contains($html,'No published stories in this section yet.') && !str_contains($html,'class="editorial-card"'));
 $lead=cds_fixture('2025-01-01 10:00:00',['analysis','guides'],['ai-security']);update_post_meta($lead,cyberdat_featured_meta_key(),true);
 $a=cds_fixture('2025-02-01 10:00:00');
 cds_check('Insufficient articles: one real card, no filler',cds_ids('editorial_format',['analysis'],$lead)===[$a] && substr_count(cds_render(),'class="editorial-card"')===1);
 cds_check('Same story may appear in Analysis and AI Security',cds_ids('category',['ai-security'],$lead)===[$a]);
 $b=cds_fixture('2025-02-02 10:00:00');$c=cds_fixture('2025-02-02 10:00:00');$d=cds_fixture('2025-02-03 10:00:00');
 cds_check('New Analysis appears automatically, date DESC then ID DESC, limit three',cds_ids('editorial_format',['analysis'],$lead)===[$d,$c,$b]);
 $guide=cds_fixture('2025-03-01 10:00:00',['guides'],['network-security']);
 $learn=cds_fixture('2025-03-02 10:00:00',['learning'],['cybersecurity-fundamentals']);
 $both=cds_fixture('2025-03-03 10:00:00',['guides','learning'],['network-security','ai-security']);
 cds_check('Guides OR Learning returns latest three without duplicate multi-format story',cds_ids('editorial_format',['guides','learning'],$lead)===[$both,$learn,$guide]);
 cds_check('Multiple categories match AI Security even when not first category',cds_ids('category',['ai-security'],$lead)===[$both,$d,$c]);
 // The marked lead belongs to all three queries and must never appear in any.
 foreach([['editorial_format',['analysis']],['category',['ai-security']],['editorial_format',['guides','learning']]] as [$tax,$terms]){
  cds_check('Featured excluded from '.$tax.' '.implode('+',$terms),!in_array($lead,cds_ids($tax,$terms,$lead),true));
 }
 foreach(['draft','private','future','password'] as $type){cds_fixture($type==='future'?'2037-01-01 10:00:00':'2025-06-01 10:00:00',['analysis','guides','learning'],['ai-security'],['post_status'=>$type==='password'?'publish':$type,'post_password'=>$type==='password'?wp_generate_password(24):'']);}
 cds_check('Draft/private/future/password posts excluded in all sections',cds_ids('editorial_format',['analysis'],$lead)===[$d,$c,$b] && cds_ids('category',['ai-security'],$lead)===[$both,$d,$c] && cds_ids('editorial_format',['guides','learning'],$lead)===[$both,$learn,$guide]);
 $new=cds_fixture('2025-04-01 10:00:00',['analysis','learning'],['ai-security','network-security']);
 cds_check('New multi-topic post immediately updates every matching section',cds_ids('editorial_format',['analysis'],$lead)===[$new,$d,$c] && cds_ids('category',['ai-security'],$lead)===[$new,$both,$d] && cds_ids('editorial_format',['guides','learning'],$lead)===[$new,$both,$learn]);
 update_post_meta($new,cyberdat_featured_meta_key(),true);
 cds_check('Changing Featured removes new story from rendered sections',!str_contains(cds_render(),'data-post-id="'.$new.'"') && str_contains(cds_render(),'data-post-id="'.$d.'"'));
 delete_post_meta($new,cyberdat_featured_meta_key());
 $html=cyberdat_section_image($d);cds_check('No image uses local SVG with dimensions and lazy loading',str_contains($html,'editorial-fallback.svg') && str_contains($html,'loading="lazy"') && str_contains($html,'width="640"'));
 $attachment=get_post_thumbnail_id($fixtures[0]->ID);set_post_thumbnail($d,$attachment);$html=cyberdat_section_image($d);
 cds_check('Core attachment markup includes srcset/sizes/alt/lazy dimensions',str_contains($html,'srcset=') && str_contains($html,'sizes=') && str_contains($html,'alt=') && str_contains($html,'loading="lazy"') && str_contains($html,'width='));
 // Bypass save sanitization ONLY on an isolated fixture to exercise output escaping.
 global $wpdb;
 $wpdb->update($wpdb->posts,['post_title'=>'<script>alert("title")</script> & Research','post_excerpt'=>'<script>alert("excerpt")</script><b>Preview</b>'],['ID'=>$d]);clean_post_cache($d);
 $html=cds_render();cds_check('Card text and attribute output do not expose script markup',!str_contains($html,'<script>') && str_contains($html,'&lt;script&gt;'));
 cds_check('Unknown taxonomy fails closed',cyberdat_section_posts('not-a-taxonomy',['analysis'])===[]);
}catch(Throwable $e){$results[]=['test'=>'Sections suite completion','status'=>'FAIL','detail'=>$e->getMessage()];}
finally{
 $_POST=[];wp_set_current_user(1);
 foreach(array_reverse($created) as $id){wp_delete_post($id,true);}
 foreach($fixtures as $p){wp_update_post(['ID'=>$p->ID,'post_status'=>$p->post_status,'post_date'=>$p->post_date,'post_date_gmt'=>$p->post_date_gmt]);}
 $_POST=$before_post;wp_set_current_user($before_user);
}
$results[]=['test'=>'Original fixture statuses, dates, content, terms and meta restored','status'=>cds_snapshot($fixtures)===$snapshot && count(get_posts(['post_type'=>'post','post_status'=>'publish','numberposts'=>-1]))===count($fixtures)?'PASS':'FAIL'];
file_put_contents(ABSPATH.'wp-content/cyberdat-preview/section-test-results.json',wp_json_encode(['environment'=>'Isolated WordPress Playground only','results'=>$results],JSON_PRETTY_PRINT));
echo wp_json_encode($results),"\n";
