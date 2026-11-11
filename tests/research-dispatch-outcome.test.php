<?php
/** CLI behavior under a real collector outcome; no WP/network/DB. */
define('ABSPATH','fixture');define('WP_CLI',true);function cdra_staging(){return true;}function cdra_need($v,$s){if(!$v){throw new RuntimeException($s);}}function cdra_json($v){return json_encode($v);}function cdra_sources(){return ['nvd'=>[]];}function cdra_discovery_registry(){return [];}function cdra_discovery_enabled(){return false;}
class CDRA_Store{function get($key,$default=null){return $key==='health:nvd'?['last_success'=>1,'next_due'=>1]:$default;}}
class CDRA_Service{public static $error=false,$scheduled=false;function __construct($s){}function sync($s,$manual,$scheduled){self::$scheduled=$scheduled;return ['errors'=>self::$error?['nvd'=>'transport']:[]];}}
class WP_CLI{static function add_command($a,$b){}static function line($s){}static function halt($code){throw new RuntimeException('exit_'.$code);}}
require __DIR__.'/../wp-content/plugins/cyberdat-research/includes/cli.php';
$c=new CDRA_CLI();$c->dispatch([],['scheduled'=>true]);if(!CDRA_Service::$scheduled){throw new RuntimeException('scheduled context lost');}echo "PASS: scheduled dispatch forwards context and successful result exits normally\n";
CDRA_Service::$error=true;try{$c->dispatch([],['scheduled'=>true]);throw new RuntimeException('false_success');}catch(RuntimeException $e){if($e->getMessage()!=='exit_1'){throw $e;}}echo "PASS: failed collector makes dispatcher fail, without fabricated service success\n";
