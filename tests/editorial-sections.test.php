<?php
/** Fast query-boundary tests without a WordPress installation or database. */
define('ABSPATH',__DIR__.'/');
class WP_Query { public $posts;public static $args;public function __construct($args){self::$args=$args;$this->posts=[(object)['ID'=>42]];} }
function taxonomy_exists($name){return in_array($name,['category','editorial_format'],true);}
require __DIR__.'/../wp-content/themes/cyberdat/inc/home-prototype.php';
$count=0;
function check($label,$pass){global $count;if(!$pass){throw new RuntimeException($label);}++$count;echo "PASS $label\n";}
foreach([['editorial_format',['analysis']],['category',['ai-security']],['editorial_format',['guides','learning']]] as [$tax,$terms]){
 $posts=cyberdat_section_posts($tax,$terms,77);$args=WP_Query::$args;
 check($tax.' public posts only',$args['post_type']==='post' && $args['post_status']==='publish' && $args['has_password']===false);
 check($tax.' bounded deterministic ordering',$args['posts_per_page']===3 && $args['orderby']===['date'=>'DESC','ID'=>'DESC'] && $args['ignore_sticky_posts']===true);
 check($tax.' Featured exclusion',$args['post__not_in']===[77]);
 check($tax.' existing term selection / OR',$args['tax_query']===[['taxonomy'=>$tax,'field'=>'slug','terms'=>$terms,'operator'=>'IN','include_children'=>false]] && $posts[0]->ID===42);
}
check('Unknown taxonomy returns no records',cyberdat_section_posts('post_tag',['analysis'])===[]);
cyberdat_section_posts('category',['ai-security']);check('No exclusion never becomes ID zero filter',WP_Query::$args['post__not_in']===[]);
// Execute the real front-page guard, replacing only its index fallback in a temp fixture.
$front=file_get_contents(__DIR__.'/../wp-content/themes/cyberdat/front-page.php');
check('Production guard precedes all output',str_contains($front,"if ( ! defined( 'CYBERDAT_PLAYGROUND' ) || ! CYBERDAT_PLAYGROUND ) {\n    require __DIR__ . '/index.php';\n    return;\n}"));
$dir=sys_get_temp_dir().'/cyberdat-guard-'.bin2hex(random_bytes(6));mkdir($dir);
file_put_contents($dir.'/front-page.php',$front);file_put_contents($dir.'/index.php','<?php echo "SAFE_INDEX";');
try{ob_start();include $dir.'/front-page.php';$output=ob_get_clean();check('Production renders only index, no demo dashboard',$output==='SAFE_INDEX');}
finally{unlink($dir.'/front-page.php');unlink($dir.'/index.php');rmdir($dir);}
echo "$count checks passed\n";
