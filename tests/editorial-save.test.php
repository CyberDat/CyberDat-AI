<?php
/** Unit tests of the real save callback; WP primitives are isolated test doubles. */
define('ABSPATH','/unit-test/');
$meta=true;$permission=true;$revision=false;$autosave=false;$type='post';$checks=0;
function add_action(...$args){}
function wp_is_post_autosave($id){return $GLOBALS['autosave'];}
function wp_is_post_revision($id){return $GLOBALS['revision'];}
function get_post_type($id){return $GLOBALS['type'];}
function wp_unslash($value){return stripslashes($value);}
function sanitize_text_field($value){return strip_tags(trim($value));}
function wp_verify_nonce($nonce,$action){return $nonce==='valid-test-nonce' && $action==='cyberdat_save_featured_story';}
function current_user_can(...$args){return $GLOBALS['permission'];}
function update_post_meta($id,$key,$value){$GLOBALS['meta']=$value;}
function delete_post_meta($id,$key){$GLOBALS['meta']=false;}
require __DIR__.'/../wp-content/themes/cyberdat/inc/editorial-lead.php';
function check_case($name,$post,$expected,$change=[]){
 global $meta,$checks;
 $meta=true;foreach($change as $k=>$v){$GLOBALS[$k]=$v;}$_POST=$post;
 cyberdat_save_featured_story(42);
 if($meta!==$expected){throw new RuntimeException('FAIL: '.$name);}
 foreach($change as $k=>$v){$GLOBALS[$k]=match($k){'type'=>'post','permission'=>true,default=>false};}
 echo 'PASS '.$name."\n";$checks++;
}
$nonce=['cyberdat_featured_nonce'=>'valid-test-nonce'];
check_case('missing nonce preserves',[],true);
check_case('invalid nonce preserves',['cyberdat_featured_nonce'=>'bad'],true);
check_case('array nonce preserves',['cyberdat_featured_nonce'=>['bad']],true);
check_case('no edit permission preserves',$nonce,true,['permission'=>false]);
check_case('revision preserves',$nonce,true,['revision'=>true]);
check_case('autosave preserves',$nonce,true,['autosave'=>true]);
check_case('non-post preserves',$nonce,true,['type'=>'page']);
check_case('array checkbox preserves',$nonce+['cyberdat_featured_story'=>['1']],true);
check_case('unexpected checkbox value preserves',$nonce+['cyberdat_featured_story'=>'0'],true);
check_case('authorized unchecked clears',$nonce,false);
$meta=false;$_POST=$nonce+['cyberdat_featured_story'=>'1'];cyberdat_save_featured_story(42);
if($meta!==true){throw new RuntimeException('FAIL: authorized checked saves');}echo "PASS authorized checked saves\n";$checks++;
define('DOING_AUTOSAVE',true);check_case('DOING_AUTOSAVE preserves',$nonce,true);
echo $checks," save-handler unit cases passed\n";
