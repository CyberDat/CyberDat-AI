#!/usr/bin/env python3
"""Read existing discovery state and dispatcher evidence, without running ingestion."""
import hashlib,importlib.util,json,os,pathlib,sys
B=pathlib.Path('/home/cyberdat/cyberdat-deploy/research-0.8.2-prepared')
try:
 if os.geteuid()!=0 or sys.argv[1:]!=['--read-only']:raise RuntimeError('Use owner sudo and --read-only')
 sys.dont_write_bytecode=True;p=B/'support.py'
 if hashlib.sha256(p.read_bytes()).hexdigest()!='40f9a8336296d20fda25da08346d8e2f2892667255d2c1ffc7b223da2043b9c9':raise RuntimeError('Support checksum mismatch')
 spec=importlib.util.spec_from_file_location('discovery_observer',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 code=r'''cdra_need(cdra_staging(),'staging_only');$s=new CDRA_Store();$out=['utc'=>gmdate('c'),'sources'=>[],'streams'=>[]];foreach(cdra_discovery_registry() as $id=>$r){if(!cdra_discovery_enabled($id,$s)){continue;}$h=$s->get('health:'.$id,[]);$window=$s->get('discovery_window:'.$id);$out['sources'][$id]=['enabled'=>true,'records'=>$s->count($id),'last_attempt'=>$h['last_attempt']??null,'last_success'=>$h['last_success']??null,'last_error'=>$h['last_error']??'','next_due'=>$h['next_due']??null,'inserted'=>$h['records_inserted_total']??0,'duplicates'=>$h['records_duplicates_total']??0,'checkpoint'=>$s->get('discovery_checkpoint:'.$id),'pending_offset'=>$window['offset']??null];}foreach($s->db->get_results("SELECT stream,COUNT(*) AS n FROM {$s->prefix}discovery GROUP BY stream",ARRAY_A) as $row){$out['streams'][$row['stream']]=(int)$row['n'];}$out['duplicate_ids']=(int)$s->db->get_var("SELECT COUNT(*) FROM (SELECT source,source_key FROM {$s->prefix}items GROUP BY source,source_key HAVING COUNT(*)>1) d");echo wp_json_encode($out);'''
 result=m.wp('eval',code,check=False)
 if result.returncode:raise RuntimeError('Read-only source status failed; raw output suppressed')
 state=json.loads(result.stdout);print('DISCOVERY STATUS: '+json.dumps(state))
 for name in ['cyberdat-research-dispatch.timer','cyberdat-research@dispatch.service']:
  values=m.unit('show',name,'--property=ActiveState','--property=LastTriggerUSec','--property=NextElapseUSecRealtime','--property=ExecMainExitTimestamp','--property=ExecMainStatus','--property=Result',check=False).stdout.decode('utf-8','replace')
  print('UNIT '+name+': '+json.dumps(dict(line.split('=',1) for line in values.splitlines() if '=' in line)))
 baseline=1794324710 # Final controlled Crossref sync in owner-confirmed 2026-11-10 batch.
 later={id:v for id,v in state['sources'].items() if (v.get('last_success') or 0)>baseline}
 print('POST-CONTROLLED-BATCH SUCCESSES: '+json.dumps(list(later)))
 print('No sync, manual request, checkpoint/cache write, timer operation or production access. Later source successes are evidence to correlate with dispatcher timing, not fabricated recurrence.')
except BaseException as e:
 print('BLOCKED: read-only observer; type='+type(e).__name__)
 if isinstance(e,RuntimeError):print('Reason: '+str(e))
 sys.exit(1)
