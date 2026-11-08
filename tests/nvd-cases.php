<?php
/** Shared NVD tests. Only official fixture scores are used; HTTP is mocked. */
function cyberdat_nvd_test_suite($fixtures,$provenance){
 $results=[];$original_index=cyberdat_nvd_index();$ids=array_unique(array_merge(array_keys($fixtures),array_keys($original_index)));$keys=['cyberdat_kev_last_good','cyberdat_nvd_index','cyberdat_nvd_runtime','cyberdat_nvd_lock'];foreach($ids as $id){$keys[]=cyberdat_nvd_option($id);}
 $saved=[];foreach($keys as $key){$saved[$key]=get_option($key,null);}
 $assert=static function($name,$ok)use(&$results){$results[]=['test'=>$name,'status'=>$ok?'PASS':'FAIL'];if(!$ok){throw new RuntimeException($name);}};
 $queue=[];$requests=[];$nested=null;
 $mock=static function($pre,$args,$url)use(&$queue,&$requests,&$nested){$requests[]=['url'=>$url,'args'=>$args];if($nested===true){$nested=cyberdat_nvd_worker();}return array_shift($queue)??new WP_Error('offline','No mocked response');};
 $response=static fn($body,$code=200,$headers=[])=>['response'=>['code'=>$code],'headers'=>array_merge(['content-type'=>'application/json'],$headers),'body'=>$body];
 add_filter('pre_http_request',$mock,10,3);
 try{
  $records=[];
  foreach($provenance['requests'] as $item){$id=$item['cve_id'];$raw=$fixtures[$id];$assert('Official response checksum '.$id,hash('sha256',$raw)===$item['sha256']);$record=cyberdat_nvd_parse($raw,$id);$assert('Official response matches KEV CVE '.$id,!is_wp_error($record) && in_array($id,array_column(cyberdat_nvd_catalog(),'cveID'),true));$records[$id]=$record;}
  foreach($provenance['selected'] as $expected){$a=$records[$expected['cve_id']]['assessment'];$assert('Chosen score/source matches independent snapshot summary '.$expected['cve_id'],$a['score']===(float)$expected['score'] && $a['version']===$expected['version'] && strtoupper($a['severity'])===$expected['severity'] && $a['source']===$expected['source']);}
  $id='CVE-2026-19868';$raw=$fixtures[$id];$d=json_decode($raw,true);
  $assert('Retry-After supports seconds and HTTP date',cyberdat_nvd_retry_after('1800',1000)===1800 && cyberdat_nvd_retry_after(gmdate('D, d M Y H:i:s',2800).' GMT',1000)===1800);
  $assert('Strict URL rejects arbitrary IDs and query injection',cyberdat_nvd_url('https://example.org')===false && cyberdat_nvd_url($id.'&x=1')===false);
  $assert('Malformed JSON rejected',is_wp_error(cyberdat_nvd_parse('{',$id)));
  $assert('Oversized JSON rejected',is_wp_error(cyberdat_nvd_parse(str_repeat(' ',1048577),$id)));
  $assert('Mismatched returned CVE rejected',is_wp_error(cyberdat_nvd_parse($raw,'CVE-2021-44228')));
  $empty=$d;$empty['vulnerabilities']=[];$empty['totalResults']=0;
  $assert('Empty NVD response means not found, not nonexistence',cyberdat_nvd_parse(json_encode($empty),$id)->get_error_code()==='nvd_not_found');
  $none=$d;$none['vulnerabilities'][0]['cve']['metrics']=[];
  $assert('Missing CVSS is null / Not rated, never zero',cyberdat_nvd_parse(json_encode($none),$id)['assessment']===null);
  $log=json_decode($fixtures['CVE-2021-44228'],true);$record=cyberdat_nvd_parse(json_encode($log),'CVE-2021-44228');
  $assert('3.1 takes priority over actual 2.0 assessment',$record['assessment']['version']==='3.1' && $record['assessment']['score']===10.0);
  unset($log['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31']);$v2=cyberdat_nvd_parse(json_encode($log),'CVE-2021-44228');
  $assert('Actual CVSS 2.0 remains numeric and Unclassified',$v2['assessment']['version']==='2.0' && $v2['assessment']['score']===9.3 && $v2['assessment']['severity']==='Unclassified');
  $fortra=json_decode($fixtures['CVE-2025-10035'],true);$a=cyberdat_nvd_parse(json_encode($fortra),'CVE-2025-10035');$fortra['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31']=array_reverse($fortra['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31']);$b=cyberdat_nvd_parse(json_encode($fortra),'CVE-2025-10035');
  $assert('NIST source wins deterministically over higher CNA score',$a===$b && $a['assessment']['source']==='nvd@nist.gov' && $a['assessment']['score']===9.8);
  foreach(['cvssMetricV40'=>'4.0','cvssMetricV30'=>'3.0'] as $field=>$version){$invalid=$none;$invalid['vulnerabilities'][0]['cve']['metrics'][$field]=[['cvssData'=>['version'=>$version]]];$assert($version.' incomplete assessment fails closed',is_wp_error(cyberdat_nvd_parse(json_encode($invalid),$id)));}
  $invalid=$d;$invalid['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']=99;$assert('Out-of-range score rejected',is_wp_error(cyberdat_nvd_parse(json_encode($invalid),$id)));
  $invalid=$d;$invalid['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']='LOW';$assert('Inconsistent severity rejected',is_wp_error(cyberdat_nvd_parse(json_encode($invalid),$id)));
  $assert('3.1 fixture does not pretend 4.0/3.0 coverage',array_reduce($records,static fn($ok,$r)=>$ok && $r['assessment']['version']==='3.1',true));
  $assert('Full queue contains only KEV IDs and is bounded',count(cyberdat_nvd_allowed())<=2000 && count(cyberdat_nvd_allowed())===1769);
  delete_option('cyberdat_nvd_index');$assert('Unloaded catalog does not count as unrated',cyberdat_nvd_coverage()['loaded']===0 && array_sum(cyberdat_nvd_coverage()['counts'])===0);
  foreach($records as $cve=>$record){cyberdat_nvd_store($record,time(),true);}
  $coverage=cyberdat_nvd_coverage();$assert('Partial coverage uses loaded denominator only',$coverage['loaded']===count($records) && $coverage['total']===1769 && array_sum($coverage['counts'])===count($records));
  $assert('Official snapshot view is Stale and not live',cyberdat_nvd_view($id)['snapshot'] && cyberdat_nvd_view($id)['status']==='Stale');
  cyberdat_nvd_store($records[$id],time(),false);$assert('Live cache freshness is seven days',cyberdat_nvd_view($id)['status']==='Fresh' && cyberdat_nvd_view($id,time()+604801)['status']==='Stale');
  $before=get_option('cyberdat_kev_last_good');$one=$before;$one['catalog']['vulnerabilities']=array_values(array_filter($before['catalog']['vulnerabilities'],static fn($r)=>$r['cveID']===$id));$one['catalog']['count']=1;
  update_option('cyberdat_kev_last_good',$one,false);
  $prepare=static function()use($records,$id){delete_option('cyberdat_nvd_runtime');cyberdat_nvd_store($records[$id],time()-604801,false);};
  foreach([429,403,404,500] as $code){$prepare();$good=get_option(cyberdat_nvd_option($id));$queue=[$response('{}',$code,['retry-after'=>'1800'])];$n=count($requests);$error=cyberdat_nvd_worker();$assert('HTTP '.$code.' keeps last-good data and respects backoff',is_wp_error($error) && get_option(cyberdat_nvd_option($id))===$good && get_option('cyberdat_nvd_runtime')['next_run']>=time()+1798 && count($requests)===$n+1);$n=count($requests);cyberdat_nvd_worker();$assert('HTTP '.$code.' cooldown prevents repeat request',count($requests)===$n);}
  foreach([new WP_Error('timeout','Mock timeout'),$response('{'),$response(json_encode($empty)),$response('{}',302)] as $bad){$prepare();$good=get_option(cyberdat_nvd_option($id));$queue=[$bad];cyberdat_nvd_worker();$assert('Timeout/JSON/missing-CVE/redirect keeps verified record',get_option(cyberdat_nvd_option($id))===$good && cyberdat_nvd_view($id)['status']==='Stale');}
  delete_option('cyberdat_nvd_runtime');$idx=cyberdat_nvd_index();$idx[$id]['next_retry']=0;update_option('cyberdat_nvd_index',$idx,false);$queue=[$response($raw)];$n=count($requests);$assert('Successful retry recovers cache freshness',cyberdat_nvd_worker()===true && cyberdat_nvd_view($id)['status']==='Fresh' && count($requests)===$n+1);
  delete_option('cyberdat_nvd_runtime');$lock=cyberdat_nvd_lock(time());$n=count($requests);$busy=cyberdat_nvd_worker();$assert('Concurrent worker locked without HTTP',is_wp_error($busy) && $busy->get_error_code()==='nvd_locked' && count($requests)===$n);$wrong=$lock;$wrong['token']='not-owner';$assert('Lock release requires matching owner',!cyberdat_nvd_unlock($wrong));cyberdat_nvd_unlock($lock);
  update_option('cyberdat_kev_last_good',$before,false);delete_option('cyberdat_nvd_index');delete_option('cyberdat_nvd_runtime');$nested=true;$queue=[$response($raw)];$n=count($requests);$assert('At most one CVE per worker and nested invocation blocked',cyberdat_nvd_worker()===true && count($requests)===$n+1 && is_wp_error($nested) && $nested->get_error_code()==='nvd_locked');
  $n=count($requests);cyberdat_nvd_worker();$assert('Global minimum request gap is persisted',count($requests)===$n);
  $next=cyberdat_nvd_next(cyberdat_nvd_index(),time());$assert('Queue resumes from next unprocessed KEV',$next==='CVE-2024-27834');
  $assert('Worker HTTP is fixed HTTPS, no redirect, bounded',count(array_filter($requests,static fn($r)=>str_starts_with($r['url'],'https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds=CVE-') && $r['args']['redirection']===0 && $r['args']['timeout']===10 && $r['args']['limit_response_size']===1048577))===count($requests));
  $bad=$records[$id];$bad['description']='<script>alert("description")</script>';cyberdat_nvd_store($bad,time(),true);$n=count($requests);ob_start();get_template_part('template-parts/home/nvd-cell',null,['id'=>$id]);$html=ob_get_clean();
  $assert('Description escapes HTML, shows source/version/check time',!str_contains($html,'<script>') && str_contains($html,'&lt;script&gt;') && str_contains($html,'CVSS 3.1') && str_contains($html,'datetime='));
  ob_start();get_template_part('template-parts/home/intelligence');$html=ob_get_clean();$assert('Dashboard keeps KEV metrics/dateAdded and explicit coverage',str_contains($html,'KEV catalog entries') && str_contains($html,'KEV additions by day') && str_contains($html,'CVSS coverage:') && !str_contains($html,'CVE-DEMO'));
  $assert('Rendering is cache-only',count($requests)===$n);cyberdat_nvd_cron();$assert('Playground/default live mode disabled',!cyberdat_nvd_live_enabled() && count($requests)===$n);
 }catch(Throwable $e){$results[]=['test'=>'NVD suite completion','status'=>'FAIL','detail'=>$e->getMessage()];}
 finally{remove_filter('pre_http_request',$mock,10);foreach($keys as $key){delete_option($key);if($saved[$key]!==null){add_option($key,$saved[$key],'',false);}}}
 $restored=true;foreach($keys as $key){if(get_option($key,null)!==$saved[$key]){$restored=false;}}$results[]=['test'=>'Original KEV and NVD fixtures fully restored','status'=>$restored?'PASS':'FAIL'];return $results;
}
