<?php
/** Real WordPress integration scenarios, executed ONLY inside Playground. */
require '/wordpress/wp-load.php';
if (!defined('CYBERDAT_PLAYGROUND') || !CYBERDAT_PLAYGROUND || ABSPATH!=='/wordpress/') { throw new RuntimeException('Playground-only test guard failed'); }
$results=[];$created=[];$reader=0;$fixtures=get_posts(['post_type'=>'post','post_status'=>'publish','numberposts'=>-1]);
$before_post=$_POST;$before_user=get_current_user_id();
function cd_check($label,$passed){global $results;$results[]=['test'=>$label,'status'=>$passed?'PASS':'FAIL'];if(!$passed){throw new RuntimeException($label);}}
function cd_fixture($date,$format='news',$status='publish',$extra=[]){
 global $created;
 $id=wp_insert_post(array_merge(['post_type'=>'post','post_status'=>$status,'post_title'=>'Isolated editorial test','post_content'=>'Test body.','post_author'=>1,'post_date'=>$date,'post_date_gmt'=>$date,'comment_status'=>'closed'], $extra),true);
 if(is_wp_error($id)){throw new RuntimeException($id->get_error_message());}
 $created[]=$id;
 if($format){$term=get_term_by('slug',$format,'editorial_format');if(!$term){throw new RuntimeException('Fixture format missing');}wp_set_post_terms($id,[$term->term_id],'editorial_format');}
 return $id;
}
try{
 wp_set_current_user(1);$_POST=[];
 foreach($fixtures as $post){wp_update_post(['ID'=>$post->ID,'post_status'=>'draft']);}
 cd_check('No published articles: no Featured and no Briefing',cyberdat_featured_story()===null && cyberdat_briefing_posts()===[]);
 ob_start();get_template_part('template-parts/home/lead');$empty=ob_get_clean();
 cd_check('Empty state is explicit and contains no fictional post links',str_contains($empty,'No published stories yet') && !str_contains($empty,'data-post-id='));
 $a=cd_fixture('2026-01-01 10:00:00','analysis');$b=cd_fixture('2026-01-02 10:00:00','guides');
 cd_check('No flags: newest public published post is fallback',cyberdat_featured_story()->ID===$b);
 update_post_meta($a,cyberdat_featured_meta_key(),true);
 cd_check('Featured may be Analysis, not just News',cyberdat_featured_story()->ID===$a);
 update_post_meta($b,cyberdat_featured_meta_key(),true);
 cd_check('Multiple flags: newest publication date wins',cyberdat_featured_story()->ID===$b);
 $tie=cd_fixture('2026-01-02 10:00:00','learning');update_post_meta($tie,cyberdat_featured_meta_key(),true);
 cd_check('Equal dates: highest post ID wins',cyberdat_featured_story()->ID===$tie);
 $draft=cd_fixture('2026-01-05 10:00:00','news','draft');update_post_meta($draft,cyberdat_featured_meta_key(),true);
 $private=cd_fixture('2026-01-06 10:00:00','news','private');update_post_meta($private,cyberdat_featured_meta_key(),true);
 $password=cd_fixture('2026-01-07 10:00:00','news','publish',['post_password'=>wp_generate_password(24)]);update_post_meta($password,cyberdat_featured_meta_key(),true);
 $future=cd_fixture('2037-01-01 10:00:00','news','future');update_post_meta($future,cyberdat_featured_meta_key(),true);
 cd_check('Draft/private/future/password-protected posts excluded',cyberdat_featured_story()->ID===$tie && cyberdat_briefing_posts()===[]);
 $n1=cd_fixture('2026-02-01 10:00:00');$n2=cd_fixture('2026-02-02 10:00:00');
 cd_check('Insufficient News: only existing stories returned',array_map('intval',wp_list_pluck(cyberdat_briefing_posts(),'ID'))===[$n2,$n1]);
 $n3=cd_fixture('2026-02-03 10:00:00');$n4=cd_fixture('2026-02-04 10:00:00');$n5=cd_fixture('2026-02-05 10:00:00');
 update_post_meta($n5,cyberdat_featured_meta_key(),true);
 cd_check('News can be Featured and is excluded from the four latest News',cyberdat_featured_story()->ID===$n5 && array_map('intval',wp_list_pluck(cyberdat_briefing_posts($n5),'ID'))===[$n4,$n3,$n2,$n1]);
 delete_post_meta($n5,cyberdat_featured_meta_key());
 cd_check('Changing Featured automatically updates Briefing',cyberdat_featured_story()->ID===$tie && array_map('intval',wp_list_pluck(cyberdat_briefing_posts($tie),'ID'))===[$n5,$n4,$n3,$n2]);
 $no_image=cyberdat_editorial_image($n1,true);
 cd_check('Missing image uses local sized fallback',str_contains($no_image,'editorial-fallback.svg') && str_contains($no_image,'width="1280"') && str_contains($no_image,'data-editorial-fallback="true"'));
 $attachment=get_post_thumbnail_id($fixtures[0]->ID);set_post_thumbnail($n1,$attachment);$with_image=cyberdat_editorial_image($n1,true);
 cd_check('Featured image uses WordPress responsive image metadata',str_contains($with_image,'srcset=') && str_contains($with_image,'sizes=') && str_contains($with_image,'fetchpriority="high"'));
 // Exercise the actual admin save handler with valid and invalid contexts.
 update_post_meta($a,cyberdat_featured_meta_key(),true);$_POST=[];cyberdat_save_featured_story($a);
 cd_check('Missing nonce preserves existing flag',(bool)get_post_meta($a,cyberdat_featured_meta_key(),true));
 $_POST=['cyberdat_featured_nonce'=>'invalid'];cyberdat_save_featured_story($a);
 cd_check('Invalid nonce cannot clear flag',(bool)get_post_meta($a,cyberdat_featured_meta_key(),true));
 $_POST=['cyberdat_featured_nonce'=>['invalid']];cyberdat_save_featured_story($a);
 cd_check('Malformed nonce cannot clear flag',(bool)get_post_meta($a,cyberdat_featured_meta_key(),true));
 $reader=wp_insert_user(['user_login'=>'cyberdat-fixture-reader-'.wp_generate_password(8,false),'user_pass'=>wp_generate_password(32),'role'=>'subscriber']);
 if(is_wp_error($reader)){throw new RuntimeException('Cannot create disposable capability test user');}
 wp_set_current_user($reader);$_POST=['cyberdat_featured_nonce'=>wp_create_nonce('cyberdat_save_featured_story')];cyberdat_save_featured_story($a);
 cd_check('Valid nonce without edit permission cannot clear flag',(bool)get_post_meta($a,cyberdat_featured_meta_key(),true));
 wp_set_current_user(1);$_POST=['cyberdat_featured_nonce'=>wp_create_nonce('cyberdat_save_featured_story'),'cyberdat_featured_story'=>['1']];cyberdat_save_featured_story($a);
 cd_check('Malformed checkbox cannot alter flag',(bool)get_post_meta($a,cyberdat_featured_meta_key(),true));
 $_POST=['cyberdat_featured_nonce'=>wp_create_nonce('cyberdat_save_featured_story')];cyberdat_save_featured_story($a);
 cd_check('Authorized unchecked box clears flag',!get_post_meta($a,cyberdat_featured_meta_key(),true));
 $_POST['cyberdat_featured_story']='1';cyberdat_save_featured_story($a);
 cd_check('Authorized checked box saves flag',(bool)get_post_meta($a,cyberdat_featured_meta_key(),true));
 $_POST=[];$revision=wp_insert_post(['post_type'=>'revision','post_status'=>'inherit','post_parent'=>$a,'post_title'=>'Revision fixture','post_name'=>$a.'-autosave-v1'],true);if(is_wp_error($revision)){throw new RuntimeException('Revision fixture failed');}$created[]=$revision;
 $_POST=['cyberdat_featured_nonce'=>wp_create_nonce('cyberdat_save_featured_story'),'cyberdat_featured_story'=>'1'];cyberdat_save_featured_story($revision);
 cd_check('Revisions/autosaves never receive Featured meta',!metadata_exists('post',$revision,cyberdat_featured_meta_key()));
 $meta=get_registered_meta_keys('post','post');cd_check('Feature meta is typed and not exposed as a writable public REST field',$meta[cyberdat_featured_meta_key()]['type']==='boolean' && $meta[cyberdat_featured_meta_key()]['show_in_rest']===false);
}catch(Throwable $e){$results[]=['test'=>'Suite completion','status'=>'FAIL','detail'=>$e->getMessage()];}
finally{
 $_POST=[];wp_set_current_user(1);
 foreach(array_reverse($created) as $id){wp_delete_post($id,true);}
 foreach($fixtures as $post){wp_update_post(['ID'=>$post->ID,'post_status'=>'publish']);}
 if($reader && !is_wp_error($reader)){require_once ABSPATH.'wp-admin/includes/user.php';wp_delete_user($reader);}
 $_POST=$before_post;wp_set_current_user($before_user);
}
$featured=cyberdat_featured_story();$briefing=cyberdat_briefing_posts($featured?$featured->ID:0);
$results[]=['test'=>'Original demo fixtures restored without duplicate lead posts','status'=>count(get_posts(['post_type'=>'post','numberposts'=>-1]))===15 && $featured && !in_array($featured->ID,wp_list_pluck($briefing,'ID'),true) ? 'PASS':'FAIL'];
$report=['environment'=>'Isolated WordPress Playground only','results'=>$results,'featured_id'=>$featured?$featured->ID:null,'briefing_ids'=>wp_list_pluck($briefing,'ID')];
file_put_contents(ABSPATH.'wp-content/cyberdat-preview/editorial-test-results.json',wp_json_encode($report,JSON_PRETTY_PRINT));
echo wp_json_encode($report),"\n";
