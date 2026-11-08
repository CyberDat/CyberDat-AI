<?php
defined('ABSPATH') || exit;
function cyberdat_research_active(){
 static $active=null;if($active!==null){return $active;}
 if(!cdra_staging()){return $active=false;}
 try{return $active=(new CDRA_Store())->get('live_enabled',false)===true;}catch(Throwable $error){return $active=is_readable('/var/lib/cyberdat-staging/research/dashboard.json');}
}
function cyberdat_research_data(){
 static $loaded=false,$data=null;if($loaded){return $data;}$loaded=true;
 if(!cyberdat_research_active()){return null;}
 try{$data=(new CDRA_Store())->get('dashboard');}catch(Throwable $error){$data=null;}
 if(!is_array($data)||($data['schema']??0)!==2){$file='/var/lib/cyberdat-staging/research/dashboard.json';if(is_readable($file)&&!is_link($file)&&filesize($file)<=12582912){$raw=@file_get_contents($file);$data=is_string($raw)?json_decode($raw,true,64):null;if(is_array($data)){$data['fallback']=true;}}}
 return is_array($data)&&($data['schema']??0)===2?$data:null;
}
function cyberdat_research_source($source,$now=null){
 $now=$now??time();$data=cyberdat_research_data();$h=$data['sources'][$source]??[];$last=$source==='nvd'?($data['nvd_last_incremental_success']??0):($h['last_success']??0);$fresh=cdra_sources()[$source]['fresh'];
 $interrupted=($h['job']??'')==='Running'&&$now-($h['last_attempt']??0)>180;
 $h['status']=!empty($h['last_error'])||$interrupted||!empty($data['fallback'])?'Sync Error':($last&&$now-$last<=$fresh?'Fresh':'Stale');
 return $h;
}
function cyberdat_research_kev_view($now=null){
 $now=$now??time();$data=cyberdat_research_data();$cache=$data['kev']??null;
 return ['status'=>cyberdat_research_source('kev',$now)['status'],'cache'=>$cache,'metrics'=>$cache?cyberdat_kev_metrics($cache['catalog'],$now):null,'reference'=>$now];
}
function cyberdat_research_nvd_view($id,$now=null){
 $data=cyberdat_research_data();$row=$data['nvd'][$id]??null;if(!$row){return null;}
 $row['status']=cyberdat_research_source('nvd',$now)['status'];if($row['status']==='Fresh'&&($now??time())-$row['checked_at']>604800){$row['status']='Stale';}return $row;
}
function cyberdat_research_coverage(){
 $data=cyberdat_research_data();$counts=['Critical'=>0,'High'=>0,'Medium'=>0,'Low'=>0,'Unrated / Unclassified'=>0];$stale=0;
 foreach(($data['nvd']??[]) as $id=>$row){$label=$row['record']['assessment']['severity']??'Unrated / Unclassified';++$counts[array_key_exists($label,$counts)?$label:'Unrated / Unclassified'];if((cyberdat_research_nvd_view($id)['status']??'Stale')!=='Fresh'){++$stale;}}
 return ['loaded'=>count($data['nvd']??[]),'total'=>$data['kev']['catalog']['count']??0,'counts'=>$counts,'snapshots'=>0,'stale'=>$stale,'indexed_cves'=>(int)($data['indexed_cves']??0),'scope'=>'kev_intersection'];
}
function cyberdat_research_status_html(){
 $data=cyberdat_research_data();if(!$data){echo '<p class="chart-caption">'.esc_html__('Research cache unavailable. No estimated values are shown.','cyberdat-research').'</p>';return;}
 echo '<div class="chart-caption" data-research-status>';
 foreach(['kev'=>'CISA KEV','nvd'=>'NVD'] as $id=>$name){$h=cyberdat_research_source($id);$success=$h['last_success']??0;
 echo '<p>'.esc_html($name.' · '.$h['status'].' · '.__('Last Successful Sync','cyberdat-research').': '.($success?gmdate('Y-m-d H:i:s',(int)$success).' UTC':__('Never','cyberdat-research'))).' · '.esc_html(__('Last received','cyberdat-research').': '.(!empty($h['last_received'])?gmdate('Y-m-d H:i:s',(int)$h['last_received']).' UTC':'—')).'</p>';
 }
 $catalog=$data['kev']['catalog']??null;if($catalog){echo '<p>'.esc_html('CISA source catalog: '.$catalog['catalogVersion'].' · '.$catalog['dateReleased']).'</p>';}
 echo '<p>'.esc_html(sprintf(__('Indexed CVEs: %1$d · NVD/KEV matches displayed: %2$d. Partial data: this is not the entire NVD.','cyberdat-research'),$data['indexed_cves'],count($data['nvd']))).'</p>';
 echo '<p>'.esc_html(__('Coverage Window (modified-date tracking):','cyberdat-research').' '.($data['nvd_origin']??'—').' → '.(!empty($data['nvd_checkpoint'])?gmdate('Y-m-d\TH:i:s\Z',$data['nvd_checkpoint']):__('first window in progress','cyberdat-research')).' · '.__('Backfill Status','cyberdat-research').': '.($data['backfill']['status']??'not_requested')).'</p>';
 echo '<p>'.esc_html(__('Selected CVSS assessments; versions are not interchangeable:','cyberdat-research').' '.implode('; ',array_map(static fn($key,$count)=>$key.': '.$count,array_keys($data['metric_versions']),array_values($data['metric_versions'])))).'</p></div>';
}
/** Future Content Agent contract: explicit approved-only, authenticated CLI export. */
function cdra_export_approved($limit=20){
 cdra_need(cdra_staging()&&defined('WP_CLI')&&WP_CLI,'cli_staging_only');$store=new CDRA_Store();$limit=max(1,min(20,(int)$limit));
 $rows=$store->db->get_results($store->db->prepare("SELECT id,payload,content_hash,manual_priority,priority,kev_confirmed,first_seen,last_seen,editorial_status FROM {$store->prefix}items WHERE editorial_status='approved_for_draft' AND approved_hash=content_hash ORDER BY COALESCE(manual_priority,priority) DESC,id DESC LIMIT %d",$limit),ARRAY_A);
 return ['schema'=>'cyberdat.research.approved.v1','untrusted_source_text'=>true,'publication_authorized'=>false,'items'=>array_map(static fn($row)=>['internal_id'=>(int)$row['id'],'content_hash'=>$row['content_hash'],'evidence'=>array_merge(json_decode($row['payload'],true),['kev_confirmed'=>(bool)$row['kev_confirmed']]),'first_seen'=>$row['first_seen'],'last_seen'=>$row['last_seen'],'processing_status'=>$row['editorial_status'],'priority'=>(int)($row['manual_priority']??$row['priority'])],$rows)];
}
