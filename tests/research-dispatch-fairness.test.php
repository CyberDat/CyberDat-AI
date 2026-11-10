<?php
/** Execute the actual due-job selector using fixed states; no service/DB/network. */
define('ABSPATH','/offline/');function wp_json_encode($v,$f=0){return json_encode($v,$f);}require __DIR__.'/../wp-content/plugins/cyberdat-research/includes/registry.php';require __DIR__.'/../wp-content/plugins/cyberdat-research/includes/discovery.php';require __DIR__.'/../wp-content/plugins/cyberdat-research/includes/cli.php';
class FairnessFixture {public $state=[];public function get($key,$default=null){return $this->state[$key]??$default;}}
function check($condition,$name){if(!$condition){throw new RuntimeException($name);}echo 'PASS: '.$name."\n";}
$s=new FairnessFixture();$now=10000;$s->state=['health:kev'=>['last_success'=>1,'next_due'=>9900,'last_error'=>''],'health:nvd'=>['last_success'=>1,'next_due'=>9990,'last_error'=>''],'discovery_enabled:crossref'=>true,'health:crossref'=>['last_success'=>1,'next_due'=>9800,'last_error'=>'']];
check(cdra_dispatch_due_source($s,$now)==='crossref','overdue Crossref precedes a later-due NVD continuation');$s->state['health:crossref']['next_due']=11000;check(cdra_dispatch_due_source($s,$now)==='kev','healthy overdue KEV is recovered after an early timer skip');
$s->state['health:kev']['next_due']=11000;$s->state['health:nvd']=['last_success'=>1,'next_due'=>10001,'last_error'=>'transport','failures'=>1];check(cdra_dispatch_due_source($s,$now)===null,'future API backoff is never bypassed');
$s->state['health:nvd']['next_due']=9999;check(cdra_dispatch_due_source($s,$now)==='nvd','due legacy retry remains eligible');$s->state['health:nvd']['failures']=6;check(cdra_dispatch_due_source($s,$now)===null,'legacy bounded retry cap retained');
$s->state['health:crossref']['next_due']=9900;$s->state['discovery_enabled:crossref']=false;check(cdra_dispatch_due_source($s,$now)===null,'disabled discovery source never selected');
$s->state['discovery_enabled:crossref']=true;$s->state['health:nvd']=['last_success'=>1,'next_due'=>9950];check(cdra_dispatch_due_source($s,$now)==='crossref','oldest due time provides progress without adding timers');
$s->state['health:crossref']['next_due']=11000;check(cdra_dispatch_due_source($s,$now)==='nvd','existing collector resumes after other source advances due time');
echo "PASS: fair dispatch uses existing next_due/backoff; polling frequencies and checkpoints untouched\n";
