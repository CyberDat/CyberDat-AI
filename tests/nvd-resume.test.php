<?php
/** Offline real pagination/state-machine tests; no network or WordPress database. */
define('ABSPATH','test');define('DB_NAME','cyberdat_staging');
function wp_json_encode($v,$f=0){return json_encode($v,$f);}
function cdra_staging(){return true;}
require __DIR__.'/../wp-content/plugins/cyberdat-research/includes/registry.php';
require __DIR__.'/../wp-content/plugins/cyberdat-research/includes/ingestion.php';
class MemoryStore {
 public $values=[],$records=[],$fail=false;
 function log($source,$code){}
 function get($k,$d=null){return $this->values[$k]??$d;}
 function put($k,$v){$this->values[$k]=$v;}
 function upsert($r){if($this->fail){throw new CDRA_Error('database_error');}$this->records[$r['source_id']]=$r;}
 function transaction($f){$a=$this->values;$b=$this->records;try{return $f();}catch(Throwable $e){$this->values=$a;$this->records=$b;throw $e;}}
}
class Pages extends CDRA_Service {
 public $script,$offsets=[];
 function __construct($s,$script){parent::__construct($s,new stdClass());$this->script=$script;}
 function page($query){$this->offsets[]=$query['startIndex'];$this->requests++;$p=array_shift($this->script);if($p instanceof Throwable){throw $p;}cdra_need(is_array($p)&&$p['index']===$query['startIndex'],'unexpected_test_offset');return [$p,['status'=>200,'headers'=>[]]];}
}
function page($offset,$ids,$total){return ['index'=>$offset,'rows'=>array_map(static fn($id)=>['source_id'=>$id],$ids),'count'=>count($ids),'total'=>$total];}
function check($ok,$label){if(!$ok){throw new RuntimeException($label);}echo "PASS: $label\n";}
function store(){ $s=new MemoryStore();$s->put('nvd_window',['start'=>'2020-01-01T00:00:00Z','end'=>'2020-01-02T00:00:00Z','index'=>0,'total'=>null]);return $s;}
$s=store();$s->put('health:nvd',['last_success'=>time(),'next_due'=>time()-1]);check(CDRA_Service::nvd_pending_due($s),'dispatcher continues a Fresh but incomplete window without a manual queue');$s->put('health:nvd',['next_due'=>time()+900]);check(!CDRA_Service::nvd_pending_due($s),'dispatcher respects backoff');$s->put('nvd_window',null);check(!CDRA_Service::nvd_pending_due($s),'completed window does not dispatch a new full import');
$s=store();$a=page(0,['CVE-2020-0001','CVE-2020-0002'],3);$b=page(2,['CVE-2020-0003'],3);
try{(new Pages($s,[$a,new CDRA_Error('http_429',900)]))->nvd();}catch(CDRA_Error $e){(new Pages($s,[]))->fail('nvd',$e);}
check($s->get('nvd_window')['index']===2&&$s->get('nvd_checkpoint')===null,'429 retains committed page and no false completed checkpoint');
check($s->get('health:nvd')['next_due']>=time()+899,'Retry-After retained in backoff');
$p=new Pages($s,[$b]);$p->nvd();check($p->offsets===[2]&&count($s->records)===3,'new worker resumes exact startIndex without downloading prior page');
$c=$s->get('nvd_last_completed_window');check($s->get('nvd_window')===null&&$c['verified_results']===3&&$s->get('nvd_checkpoint')===strtotime('2020-01-02 UTC'),'all contiguous unique pages required before durable completion checkpoint');
$s=store();$s->put('nvd_window',['start'=>'2020-01-01T00:00:00Z','end'=>'2020-01-02T00:00:00Z','index'=>2,'total'=>3]);$p=new Pages($s,[$a,$b]);$p->nvd();check($p->offsets===[0,2]&&$s->get('nvd_last_completed_window')['verified_results']===3,'legacy cursor prefix audited once without discarding its committed position');
$s=store();$s->fail=true;try{(new Pages($s,[$a]))->nvd();}catch(CDRA_Error $e){}check($s->get('nvd_window')['index']===0&&!$s->records,'failed transaction retains cursor and records atomically');
$s=store();try{(new Pages($s,[$a,page(2,['CVE-2020-0002'],3)]))->nvd();}catch(CDRA_Error $e){check($e->getMessage()==='nvd_pagination_overlap','duplicate across pages detected');}check($s->get('nvd_checkpoint')===null&&$s->get('nvd_window')['index']===0,'moving pagination is not declared complete');
$s=store();try{(new Pages($s,[$a,page(2,['CVE-2020-0003'],4)]))->nvd();}catch(CDRA_Error $e){check($e->getMessage()==='nvd_pagination_changed','changed total invalidates offsets safely');}check($s->get('nvd_checkpoint')===null&&count($s->records)===2,'changed total retains last-good rows without false completion');
foreach(['http_503','transport'] as $code){$s=store();try{(new Pages($s,[$a,new CDRA_Error($code)]))->nvd();}catch(CDRA_Error $e){(new Pages($s,[]))->fail('nvd',$e);}check($s->get('nvd_window')['index']===2&&$s->get('health:nvd')['next_due']>=time()+299,$code.' retains page and applies backoff');}
echo "PASS: NVD pagination/resumption tests; no network or database accessed\n";
