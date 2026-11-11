<?php
defined('ABSPATH') || exit;
class CDCA_CLI {
 public function install(){cdca_need(cdca_stage(),'staging_only');CDCA_Store::install();WP_CLI::success('Additive Content schema ready. No selection, source fetch or publication.');}
 public function status(){cdca_need(cdca_stage(),'staging_only');$s=new CDCA_Store();WP_CLI::line(cdca_json(['mode'=>'mock_only','queue'=>$s->db->get_results("SELECT status,is_test,COUNT(*) AS count FROM {$s->p}jobs GROUP BY status,is_test",ARRAY_A),'draft_versions'=>(int)$s->db->get_var("SELECT COUNT(*) FROM {$s->p}versions"),'automatic_publication'=>false]));}
 public function fixture(){cdca_need(cdca_stage(),'staging_only');$s=new CDCA_Store();$id=$s->create(cdca_fixture(),'news',true,'owner-cli');$j=$s->read($id);if($j['status']==='selected'){$s->transition($id,'queued',(int)$j['revision'],'owner-cli');}WP_CLI::line(cdca_json(['id'=>$id,'is_test'=>true,'status'=>$s->read($id)['status']]));}
 /**
  * Import unchanged editor-selected Research evidence.
  * @synopsis --item=<id> --template=<template>
  */
 public function select($args,$options){cdca_need(cdca_stage(),'staging_only');$id=(int)($options['item']??0);$handoffs=cdra_discovery_handoff(50);$e=cdca_selected_evidence($id);cdca_need(in_array($e['topic_id'],array_column($handoffs,'topic_id'),true),'handoff_not_available');$job=(new CDCA_Store())->create($e,$options['template']??'',false,'owner-cli');WP_CLI::line(cdca_json(['id'=>$job,'status'=>'selected','is_test'=>false]));}
 /** Inspect real source data without selection, job creation or HTTP.
  * @synopsis --item=<id> --template=<template>
  */
 public function evidence_preview($args,$options){$e=cdca_research_evidence((int)($options['item']??0),false);WP_CLI::line(cdca_json(cdca_brief($e,$options['template']??'news',false)));}
 /** Additive evidence tables only. */
 public function evidence_install(){CDCA_Evidence_Store::install();WP_CLI::success('Two additive evidence tables; existing jobs/decisions retained.');}
 /** One bounded, explicitly selected job; never called by a page or Research scheduler.
  * @synopsis --job=<id> [--network]
  */
 public function enrich($args,$options){WP_CLI::line(cdca_json(cdca_enrich((int)($options['job']??0),isset($options['network']))));}
 public function evidence_test(){require CDCA_DIR.'/tests/evidence-database.php';cdca_evidence_database_tests();}
 public function test(){cdca_need(cdca_stage(),'staging_only');require CDCA_DIR.'/tests/database.php';cdca_database_tests();}
}
if(defined('WP_CLI')&&WP_CLI&&class_exists('WP_CLI')){WP_CLI::add_command('cyberdat-content','CDCA_CLI');}
