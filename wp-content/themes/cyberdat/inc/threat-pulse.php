<?php
/** Homepage presentation only. Reads the existing Research projection; never fetches or writes. */
defined('ABSPATH') || exit;
function cyberdat_pulse_period($series,$days){
 if(!is_array($series)||!in_array($days,[7,30,90],true)){return null;}
 $values=array_slice($series,-$days,null,true);
 if(count($values)!==$days){return null;}$previous=null;$positive=0;
 foreach($values as $date=>$value){
  if(!is_string($date)||!preg_match('/^\d{4}-\d{2}-\d{2}$/D',$date)||!is_int($value)||$value<0){return null;}
  $ts=strtotime($date.' UTC');if(!$ts||gmdate('Y-m-d',$ts)!==$date||($previous!==null&&$ts-$previous!==86400)){return null;}$previous=$ts;if($value>0){$positive++;}
 }
 // Two distinct observed publication/addition days are the minimum for a trend.
 return ['values'=>$values,'total'=>array_sum($values),'available'=>$positive>=2];
}
function cyberdat_pulse_signal($feed,$now){
 // Bounded existing feed (20/source): last 30 publication days, confirmed KEV first,
 // then selected CVSS severity, then source publication date, source and ID as stable ties.
 // Import/last_seen timestamps and queue insertion order are deliberately excluded.
 $rank=['Critical'=>5,'High'=>4,'Medium'=>3,'Low'=>2,'None'=>1,'Unrated'=>0];$rows=[];
 foreach($feed as $row){$published=strtotime(($row['published']??'').' UTC');
  if(!$published||$published>$now||$published<$now-30*86400||!in_array($row['kind']??'',['cve','advisory'],true)||!preg_match('~^https://~i',$row['url']??'')||empty($row['title'])){continue;}
  $rows[]=$row;
 }
 usort($rows,static fn($a,$b)=>((int)!empty($b['kev'])<=>(int)!empty($a['kev']))?:(($rank[$b['severity']]??0)<=>($rank[$a['severity']]??0))?:strcmp($b['published'],$a['published'])?:strcmp($a['source'],$b['source'])?:strcmp($a['id'],$b['id']));
 return $rows[0]??null;
}
function cyberdat_pulse_sync($data,$source){
 $h=$data['source_health'][$source]??[];$at=(int)($h['last_success']??0);
 $specs=function_exists('cdra_sources')?cdra_sources():[];$fresh=$specs[$source]['fresh']??($source==='kev'?12*3600:6*3600);$now=time();
 $interrupted=($h['job']??'')==='Running'&&$now-($h['last_attempt']??0)>180;
 $status=!empty($h['last_error'])||$interrupted?'Sync Error':($at>($data['generated_at']??0)?'Projection pending':($at&&$now-$at<=$fresh&&$now-($data['generated_at']??0)<=$fresh?'Fresh':'Stale'));
 return ['at'=>$at?gmdate('Y-m-d H:i',$at).' UTC':__('Not available','cyberdat'),'status'=>$status];
}
function cyberdat_pulse_spark($series,$days,$label,$source){
 $period=cyberdat_pulse_period($series,$days);$values=$period['values']??[];$available=$period&&$period['available'];
 echo '<div class="tp-spark" data-pulse-series="'.esc_attr(wp_json_encode($series)).'" data-series-source="'.esc_attr($source).'" data-series-label="'.esc_attr($label).'">';
 echo '<svg viewBox="0 0 280 52" role="img" aria-label="'.esc_attr($label).'"'.(!$available?' hidden':'').'><title>'.esc_html($label).'</title><path class="tp-guide" d="M4 46H276"/><polyline class="tp-line" points="';
 $points=[];$max=$values?max(1,max($values)):1;$i=0;foreach($values as $v){$points[]=round(4+272*$i/max(1,count($values)-1),2).','.round(46-40*$v/$max,2);$i++;}echo esc_attr(implode(' ',$points));echo '"/></svg>';
 $summary=$available?sprintf(__('%1$d days · %2$d records · UTC daily %3$s','cyberdat'),$days,$period['total'],$label):__('Insufficient dated observations for a trend.','cyberdat');
 echo '<span data-spark-summary>'.esc_html($summary).'</span><details class="tp-data"><summary>'.esc_html__('Inspect daily counts','cyberdat').'</summary><div data-spark-table><table><caption>'.esc_html($label.' · '.$days.' days · UTC').'</caption><thead><tr><th>Date</th><th>Records</th></tr></thead><tbody>';
 foreach($values as $date=>$value){echo '<tr><th>'.esc_html($date).'</th><td>'.esc_html($value).'</td></tr>';}
 echo '</tbody></table></div></details></div>';
}
