<?php
/** Shared assertions against the actual module; HTTP always intercepted. */
function cyberdat_kev_test_suite($raw,$provenance){
 $results=[];$keys=['cyberdat_kev_last_good','cyberdat_kev_attempt','cyberdat_kev_lock'];$saved=[];
 foreach($keys as $key){$saved[$key]=get_option($key,null);delete_option($key);}
 $assert=static function($label,$ok)use(&$results){$results[]=['test'=>$label,'status'=>$ok?'PASS':'FAIL'];if(!$ok){throw new RuntimeException($label);}};
 $requests=[];$queue=[];$nested=null;
 $mock=static function($pre,$args,$url)use(&$requests,&$queue,&$nested){
  $requests[]=['url'=>$url,'args'=>$args];
  if($nested===true){$nested=cyberdat_kev_refresh();}
  return array_shift($queue) ?? new WP_Error('mock_unavailable','Offline test response');
 };
 $response=static function($body,$code=200,$type='application/json'){return ['response'=>['code'=>$code],'headers'=>['content-type'=>$type],'body'=>$body];};
 add_filter('pre_http_request',$mock,10,3);
 try{
  $at=(new DateTimeImmutable($provenance['retrieved_at']))->getTimestamp();
  $catalog=cyberdat_kev_validate($raw,max(time(),$at));
  $assert('Official full snapshot validates',!is_wp_error($catalog) && $catalog['count']===$provenance['count']);
  $assert('Snapshot SHA-256 matches provenance',hash('sha256',$raw)===$provenance['sha256']);
  $m=cyberdat_kev_metrics($catalog,$at);$e=$provenance['expected_metrics'];
  $assert('Official snapshot metrics match independent Python counts',[$m['total'],$m['seven'],$m['thirty'],$m['ransomware']]===[$e['total'],$e['seven'],$e['thirty'],$e['ransomware']]);
  $assert('Malformed JSON rejected',is_wp_error(cyberdat_kev_validate('{')));
  $assert('Oversized response rejected',is_wp_error(cyberdat_kev_validate(str_repeat(' ',4194305))));
  $d=json_decode($raw,true);$bad=$d;$bad['count']++;
  $assert('Count mismatch rejected',is_wp_error(cyberdat_kev_validate(json_encode($bad))));
  $bad=$d;$bad['vulnerabilities'][]=$bad['vulnerabilities'][0];$bad['count']++;
  $assert('Duplicate CVE rejected without double counting',is_wp_error(cyberdat_kev_validate(json_encode($bad))));
  foreach(['2026-02-30','not-a-date',gmdate('Y-m-d',time()+86400*365)] as $date){$bad=$d;$bad['vulnerabilities'][0]['dateAdded']=$date;$assert('Invalid/future dateAdded rejected: '.$date,is_wp_error(cyberdat_kev_validate(json_encode($bad))));}
  $bad=$d;$bad['dateReleased']='2026-02-30T10:00:00Z';$assert('Invalid calendar release rejected',is_wp_error(cyberdat_kev_validate(json_encode($bad))));
  $bad=$d;$bad['vulnerabilities'][0]['cveID']='not-a-cve';$assert('Invalid identifier rejected',is_wp_error(cyberdat_kev_validate(json_encode($bad))));
  $bad=$d;$bad['vulnerabilities'][0]['knownRansomwareCampaignUse']='No';$assert('Ransomware Unknown never becomes No',is_wp_error(cyberdat_kev_validate(json_encode($bad))));
  $empty=$d;$empty['vulnerabilities']=[];$empty['count']=0;$zero=cyberdat_kev_validate(json_encode($empty));
  $assert('Structurally valid empty catalog yields zero counts',!is_wp_error($zero) && cyberdat_kev_metrics($zero,$at)['total']===0);
  $today=cyberdat_kev_day(gmdate('Y-m-d',$at));$window=['count'=>6,'vulnerabilities'=>[]];
  foreach([0,6,7,29,30,-1] as $offset){$row=$catalog['vulnerabilities'][0];$row['dateAdded']=gmdate('Y-m-d',$today-$offset*86400);$window['vulnerabilities'][]=$row;}
  $bound=cyberdat_kev_metrics($window,$at);$assert('UTC windows include today/6/29 and exclude 7/30/future', $bound['seven']===2 && $bound['thirty']===4 && array_sum($bound['days'])===2);
  $assert('No cache reports Unavailable',cyberdat_kev_view()['status']==='Unavailable');
  cyberdat_kev_store($zero,cyberdat_kev_sources()[0],$at,true);ob_start();get_template_part('template-parts/home/intelligence');$html=ob_get_clean();
  $assert('Empty verified catalog has no fabricated CVE rows',str_contains($html,'No KEV entries in the verified catalog.') && !str_contains($html,'CVE-DEMO'));
  delete_option('cyberdat_kev_last_good');ob_start();get_template_part('template-parts/home/intelligence');$html=ob_get_clean();
  $assert('Unavailable markup never invents metrics',str_contains($html,'data-kev-status="Unavailable"') && str_contains($html,'No successful import yet.'));
  cyberdat_kev_store($catalog,cyberdat_kev_sources()[0],$at,true);
  $assert('Official snapshot is always Stale and not live',cyberdat_kev_view($at)['status']==='Stale');
  $old=get_option('cyberdat_kev_last_good');$queue=[$response('Forbidden',403),new WP_Error('timeout','Mock timeout')];
  $error=cyberdat_kev_refresh();
  $assert('HTTP error/timeout preserve complete last-good cache',is_wp_error($error) && get_option('cyberdat_kev_last_good')===$old);
  $n=count($requests);$error=cyberdat_kev_refresh();$assert('Repeat failures are rate limited without HTTP',is_wp_error($error) && $error->get_error_code()==='kev_throttled' && count($requests)===$n);
  delete_option('cyberdat_kev_attempt');$queue=[$response('{'),$response('{')];cyberdat_kev_refresh();
  $assert('Invalid source JSON preserves last good',get_option('cyberdat_kev_last_good')===$old);
  delete_option('cyberdat_kev_attempt');$queue=[$response(json_encode($empty)),$response(json_encode($empty))];cyberdat_kev_refresh();
  $assert('Unexpected empty update never wipes a nonempty cache',get_option('cyberdat_kev_last_good')===$old);
  delete_option('cyberdat_kev_attempt');$queue=[$response($raw,302),$response($raw,200,'text/html')];cyberdat_kev_refresh();
  $assert('Redirect and HTML response rejected',get_option('cyberdat_kev_last_good')===$old);
  delete_option('cyberdat_kev_attempt');$queue=[$response('{'),$response($raw,200,'text/plain; charset=utf-8')];$ok=cyberdat_kev_refresh();
  $assert('Official GitHub fallback accepted after invalid canonical response',$ok===true && get_option('cyberdat_kev_last_good')['source']===cyberdat_kev_sources()[1]);
  $assert('Successful verification marks live cache Fresh',cyberdat_kev_view()['status']==='Fresh');
  $good=get_option('cyberdat_kev_last_good');
  delete_option('cyberdat_kev_attempt');$older=$d;$older['dateReleased']='2021-01-01T10:00:00Z';$older['catalogVersion']='2021.01.01';$older['vulnerabilities']=[];$older['count']=0;
  $queue=[$response(json_encode($older)),$response(json_encode($older))];cyberdat_kev_refresh();
  $assert('Older or unexpectedly empty source cannot replace verified version',get_option('cyberdat_kev_last_good')===$good);
  $older=$d;$older['dateReleased']='2026-11-05T10:00:00Z';$older['catalogVersion']='2026.11.05';foreach($older['vulnerabilities'] as &$oldrow){if($oldrow['dateAdded']>'2026-11-05'){$oldrow['dateAdded']='2026-11-05';}}unset($oldrow);
  delete_option('cyberdat_kev_attempt');$queue=[$response(json_encode($older)),$response(json_encode($older))];cyberdat_kev_refresh();
  $assert('Older nonempty catalog rejected as rollback',get_option('cyberdat_kev_last_good')===$good);
  $assert('Live cache older than 24 hours is Stale',cyberdat_kev_view($good['fetched_at']+86401)['status']==='Stale');
  delete_option('cyberdat_kev_attempt');$queue=[$response('failure',500),$response('failure',500)];cyberdat_kev_refresh();
  $assert('Failed revalidation marks recent retained data Stale',cyberdat_kev_view()['status']==='Stale' && get_option('cyberdat_kev_last_good')===$good);
  delete_option('cyberdat_kev_attempt');$lock=cyberdat_kev_lock(time());$n=count($requests);$busy=cyberdat_kev_refresh();
  $assert('Concurrent refresh blocked before HTTP',is_array($lock) && is_wp_error($busy) && $busy->get_error_code()==='kev_locked' && count($requests)===$n);
  $wrong=$lock;$wrong['token']='not-owner';$assert('Wrong owner cannot release lock',!cyberdat_kev_unlock($wrong) && get_option('cyberdat_kev_lock')===$lock);
  cyberdat_kev_unlock($lock);$expired=['token'=>'expired-owner','expires'=>time()-1];add_option('cyberdat_kev_lock',$expired,'',false);$next=cyberdat_kev_lock(time());
  $assert('Expired lock recovered atomically and old owner cannot unlock replacement',is_array($next) && !cyberdat_kev_unlock($expired) && get_option('cyberdat_kev_lock')===$next);cyberdat_kev_unlock($next);
  $nested=true;$queue=[$response($raw)];$ok=cyberdat_kev_refresh();$assert('Overlapping invocation during HTTP is blocked',$ok===true && is_wp_error($nested) && $nested->get_error_code()==='kev_locked');
  $assert('Every HTTP request uses only two exact official URLs and strict bounds',count($requests)>0 && count(array_filter($requests,static function($r){return in_array($r['url'],cyberdat_kev_sources(),true) && $r['args']['redirection']===0 && $r['args']['timeout']===8 && $r['args']['sslverify']===true && $r['args']['limit_response_size']===4194305;}))===count($requests));
  $bad=$catalog;$bad['vulnerabilities'][0]['product']='<script>alert("source")</script>';
  cyberdat_kev_store($bad,cyberdat_kev_sources()[0],$at,true);$n=count($requests);ob_start();get_template_part('template-parts/home/intelligence');$html=ob_get_clean();
  $assert('External text escaped in HTML',!str_contains($html,'<script>') && str_contains($html,'&lt;script&gt;'));
  $assert('Rendering uses cache only without HTTP',count($requests)===$n);
  $assert('No fictional CVE or inferred severity values in dashboard',!str_contains($html,'CVE-DEMO') && str_contains($html,'No inferred scores') && !str_contains($html,'severity-critical'));
  $n=count($requests);cyberdat_kev_schedule();cyberdat_kev_cron();$assert('Default-disabled Cron performs no HTTP',!cyberdat_kev_live_enabled() && count($requests)===$n);
 }catch(Throwable $e){$results[]=['test'=>'KEV suite completion','status'=>'FAIL','detail'=>$e->getMessage()];}
 finally{
  remove_filter('pre_http_request',$mock,10);
  foreach($keys as $key){delete_option($key);if($saved[$key]!==null){add_option($key,$saved[$key],'',false);}}
 }
 $restored=true;foreach($keys as $key){if(get_option($key,null)!==$saved[$key]){$restored=false;}}
 $results[]=['test'=>'Original cache, attempt and lock restored','status'=>$restored?'PASS':'FAIL'];
 return $results;
}
