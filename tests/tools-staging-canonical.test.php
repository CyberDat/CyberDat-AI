<?php
namespace RankMath\Frontend { class Head { public $calls=0; public function canonical() { $this->calls++; } } }
namespace {
define('ABSPATH','/fixture/');$env='staging';$singular=true;$status='publish';$slug='log-anonymizer';$ready=true;$native=false;$head=new \RankMath\Frontend\Head();
function get_queried_object_id(){return 51;}
function get_post($id){global $status,$slug;return(object)['post_status'=>$status,'post_name'=>$slug];}
function wp_get_environment_type(){global $env;return $env;}
function is_singular($type){global $singular;return $singular;}
function cyberdat_tool_ready($id){global $ready;return $ready;}
function rank_math(){global $head;return(object)['head'=>$head];}
function has_action($name,$callback){global $native;return $native?20:false;}
$s=file_get_contents(__DIR__.'/../wp-content/themes/cyberdat/inc/tools.php');$start=strpos($s,'function cyberdat_tools_staging_canonical()');$end=strpos($s,"add_action( 'rank_math/head', 'cyberdat_tools_staging_canonical'",$start);eval(substr($s,$start,$end-$start));
function check($condition){if(!$condition)throw new \RuntimeException('canonical scope regression');}
cyberdat_tools_staging_canonical();check($head->calls===1);
$native=true;cyberdat_tools_staging_canonical();check($head->calls===1);$native=false;
foreach(['production','development'] as $v){$env=$v;cyberdat_tools_staging_canonical();check($head->calls===1);}$env='staging';
$status='draft';cyberdat_tools_staging_canonical();check($head->calls===1);$status='publish';
$slug='other-page';cyberdat_tools_staging_canonical();check($head->calls===1);$slug='mcp-security-checker';
$ready=false;cyberdat_tools_staging_canonical();check($head->calls===1);$ready=true;
$singular=false;cyberdat_tools_staging_canonical();check($head->calls===1);$singular=true;
cyberdat_tools_staging_canonical();check($head->calls===2);
echo "PASS: Rank Math sole generator; native-hook duplication, environment, page, status and readiness gates\n";
}
