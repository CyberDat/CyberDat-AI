<?php
/** Finite time-range coverage: no reliance on offsets across a changing result set. */
defined('ABSPATH') || exit;
function cdra_nvd_split_range($range){
 [$start,$end]=$range;cdra_need($end-$start>1,'nvd_dense_slice');$mid=$start+intdiv($end-$start,2);
 // NVD bounds are inclusive; overlap at the midpoint avoids fractional-second gaps.
 return [[$start,$mid],[$mid,$end]];
}
function cdra_nvd_certified_ids($segments){$ids=[];foreach($segments as $segment){foreach($segment['ids'] as $id){$ids[$id]=true;}}return array_keys($ids);}
function cdra_nvd_coverage_complete($proof){
 $at=$proof['start'];foreach($proof['segments'] as $segment){if($segment['start']!==$at||$segment['count']!==$segment['total']||count($segment['ids'])!==$segment['total']){return false;}$at=$segment['end'];}
 return !$proof['pending']&&$at===$proof['end'];
}
function cdra_nvd_progress($service,$backfill=false){
 $s=$service->store;$key=$backfill?'nvd_backfill_window':'nvd_window';$cpkey=$backfill?'nvd_backfill_checkpoint':'nvd_checkpoint';$max=$service->requests===0?2:1;
 for($step=0;$step<$max;$step++){
  $window=$s->get($key);
  if(!$window){
   if($backfill){$request=$s->get('backfill');cdra_need($request&&$request['status']==='active','no_backfill_requested');$checkpoint=$s->get($cpkey,$request['start']);$end=min($request['end'],$checkpoint+3600);$start=$checkpoint;}
   else{$safe_end=time()-600;$checkpoint=$s->get($cpkey);$start=$checkpoint?$checkpoint-7200:$safe_end-3600;$end=$checkpoint?min($safe_end,$checkpoint+3600):$safe_end;}
   if($end<=$start||(!$backfill&&$checkpoint&&$end<=$checkpoint)){if(!$backfill){$h=$s->get('health:nvd',[]);$h['job']='Idle';$h['last_run_outcome']='no_request_window_not_due';$h['next_due']=time()+cdra_spec('nvd')['interval'];$s->put('health:nvd',$h);}return;}
   $window=['start'=>gmdate('Y-m-d\TH:i:s\Z',$start),'end'=>gmdate('Y-m-d\TH:i:s\Z',$end),'index'=>0,'total'=>null,'pages'=>[]];
  }
  if(!isset($window['time_proof'])){
   $window['strategy']='single_response_time_slices_v1';
   $window['legacy_prefix']=['index'=>$window['index'],'total'=>$window['total'],'pages'=>$window['pages']??[]];
   $start=cdra_time($window['start']);$end=cdra_time($window['end']);
   $window['time_proof']=['start'=>$start,'end'=>$end,'pending'=>[[$start,$end]],'segments'=>[],'certified_unique'=>0,'covered_until'=>$start,'probes'=>0];
   // Preserve the existing window, cursor, pages, rows and completed checkpoint.
   $s->put($key,$window);
  }
  $proof=$window['time_proof'];cdra_need(count($proof['segments'])+count($proof['pending'])<=2048,'nvd_proof_capacity');
  $range=$proof['pending'][0];[$start,$end]=$range;$query=['lastModStartDate'=>gmdate('Y-m-d\TH:i:s\Z',$start),'lastModEndDate'=>gmdate('Y-m-d\TH:i:s\Z',$end),'resultsPerPage'=>200,'startIndex'=>0];
  try{[$page,$response]=$service->page($query);}catch(CDRA_Error $e){
   if($e->getMessage()!=='response_size'){throw $e;}
   array_shift($proof['pending']);$proof['pending']=array_merge(cdra_nvd_split_range($range),$proof['pending']);$proof['probes']++;$window['time_proof']=$proof;$s->put($key,$window);
   $health=$s->get('health:nvd',[]);$health['job']='Idle';$health['next_due']=time()+300;$health['last_progress']='split_response_size';$s->put('health:nvd',$health);return;
  }
  $done=false;$s->transaction(function()use($s,$page,$response,$range,&$proof,&$window,&$done,$key,$cpkey,$backfill,$service){
   foreach($page['rows'] as $record){$s->upsert($record);}
   $proof['probes']++;array_shift($proof['pending']);
   if($page['index']===0&&$page['count']===$page['total']){
    $ids=array_column($page['rows'],'source_id');$proof['segments'][]=['start'=>$range[0],'end'=>$range[1],'count'=>$page['count'],'total'=>$page['total'],'ids'=>$ids,'ids_hash'=>hash('sha256',implode("\n",$ids)),'verified_at'=>time()];$proof['covered_until']=$range[1];
   }else{$proof['pending']=array_merge(cdra_nvd_split_range($range),$proof['pending']);}
   $certified=cdra_nvd_certified_ids($proof['segments']);cdra_need(count($certified)<=5000,'nvd_proof_capacity');$proof['certified_unique']=count($certified);$window['time_proof']=$proof;
   $done=cdra_nvd_coverage_complete($proof);
   if($done){
    // A single atomic API response proves each covered slice, rather than an unstable
    // totalResults comparison across pages. Later modifications belong to later windows.
    $window['pages']=[];$window['pages_format']='time_proof.segments';$window['completed_at']=time();$window['status']='Complete';$window['verified_results']=count($certified);$window['index']=count($certified);$window['total']=count($certified);
    $window['completion_basis']='contiguous inclusive time slices, each returned completely in one API response; not an API snapshot';
    $s->put($cpkey,max((int)$s->get($cpkey,0),cdra_time($window['end'])));$s->put($key,null);$s->put($backfill?'nvd_last_completed_backfill':'nvd_last_completed_window',$window);
   }else{$s->put($key,$window);}
   if(!$backfill){$s->put('nvd_origin',$s->get('nvd_origin',$window['start']));$service->success('nvd',$response);$s->put('nvd_last_incremental_success',time());$h=$s->get('health:nvd');$h['catchup_pending']=$done&&cdra_time($window['end'])<time()-600;if(!$done||$h['catchup_pending']){$h['next_due']=time()+300;}$s->put('health:nvd',$h);}
   else{$request=$s->get('backfill');$request['last_success']=time();$request['next_due']=time()+7200;if($done&&cdra_time($window['end'])>=$request['end']){$request['status']='complete';}$s->put('backfill',$request);}
  });
  if($done){break;}
 }
}

/** Public projections carry progress counts, never private page/identifier ledgers. */
function cdra_nvd_progress_view($window){
 if(!is_array($window)){return $window;}
 if(isset($window['time_proof'])){$p=$window['time_proof'];$window['time_progress']=['covered_until'=>gmdate('Y-m-d\TH:i:s\Z',$p['covered_until']),'target_end'=>gmdate('Y-m-d\TH:i:s\Z',$p['end']),'certified_unique'=>$p['certified_unique'],'completed_slices'=>count($p['segments']),'pending_slices'=>count($p['pending']),'probes'=>$p['probes']];}
 unset($window['pages'],$window['time_proof'],$window['legacy_prefix']);return $window;
}
function cdra_nvd_window_label($window){
 if(!is_array($window)){return 'Not recorded';}
 $p=$window['time_progress']??(isset($window['time_proof'])?cdra_nvd_progress_view($window)['time_progress']:null);
 if($p){return 'Verified through '.$p['covered_until'].' · '.$p['completed_slices'].' completed time slices · '.$p['pending_slices'].' pending · '.$p['certified_unique'].' unique CVEs in verified slices';}
 return 'Processed '.(int)($window['index']??0).' / '.($window['total']??'unknown').' results';
}
