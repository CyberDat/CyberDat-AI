<?php
// Test the real helper under WP-CLI-like include scope; fake read-only WP adapter.
$source=file_get_contents(__DIR__.'/../wp-state.php');
$dir=sys_get_temp_dir().'/cd-snapshot-scope-'.bin2hex(random_bytes(5));mkdir($dir,0700);
file_put_contents($dir.'/wp-state.php',$source);
file_put_contents($dir.'/staging-contract.php','<?php function cd_tools_assert_staging(){ $GLOBALS["identity_calls"] = ($GLOBALS["identity_calls"] ?? 0)+1; }');
class SnapshotDB {
 public $posts='fixture_posts';public $postmeta='fixture_postmeta';public $last_error='';
 function get_row($sql,$mode){return ['ID'=>'1','post_status'=>'publish'];}
 function get_results($sql,$mode){return [];}
 function prepare($sql,...$args){return $sql;}
}
function wp_json_encode($v,$flags=0){return json_encode($v,$flags);}
define('ARRAY_A','ARRAY_A');$GLOBALS['wpdb']=new SnapshotDB();
set_error_handler(function($n,$message){throw new RuntimeException('Unexpected warning in snapshot fixture');});
try {
 ob_start();(function($file){$args=['snapshot'];include $file;})($dir.'/wp-state.php');$raw=ob_get_clean();$d=json_decode($raw,true,32,JSON_THROW_ON_ERROR);
 if(array_keys($d['pages'])!==['log-anonymizer','prompt-injection-detector','lotl-command-analyzer','mcp-security-checker'])throw new RuntimeException('Snapshot omits canonical tools');
 if(($GLOBALS['identity_calls']??0)!==1)throw new RuntimeException('Identity gate not called');
 if(array_filter($d['pages']))throw new RuntimeException('Fixture should have no page records');
 echo "PASS: WP-CLI-like local include scope, all four slots, identity gate and zero warnings\n";
} finally {if(ob_get_level())ob_end_clean();restore_error_handler();unlink($dir.'/wp-state.php');unlink($dir.'/staging-contract.php');rmdir($dir);}
