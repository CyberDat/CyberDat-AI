<?php
defined('ABSPATH') || exit;
function cdra_editorial_input($input){
 $id=$input['item_id']??'';$status=$input['status']??'';$raw=$input['priority']??'';$hash=$input['content_hash']??'';
 cdra_need(is_scalar($id)&&ctype_digit((string)$id)&&(int)$id>0&&is_string($status)&&isset(cdra_statuses()[$status])&&is_string($hash)&&preg_match('/^[a-f0-9]{64}$/D',$hash),'invalid_editorial_input');
 cdra_need(is_string($raw)&&($raw===''||(ctype_digit($raw)&&(int)$raw<=100)),'invalid_priority');
 return [(int)$id,$status,$raw===''?null:(int)$raw,$hash];
}
function cdra_editorial_authorized($input,$nonce){
 cdra_need(cdra_staging()&&current_user_can('manage_options'),'editorial_forbidden');$values=cdra_editorial_input($input);cdra_need(is_string($nonce)&&wp_verify_nonce($nonce,'cdra_item_'.$values[0]),'editorial_nonce');return $values;
}
function cdra_admin_hooks(){
 add_action('admin_menu',static function(){add_menu_page('CyberDat Research','CyberDat','manage_options','cyberdat-research','cdra_admin_page','dashicons-shield',58);add_submenu_page('cyberdat-research','Research Queue','Research Queue','manage_options','cyberdat-research','cdra_admin_page');});
 add_action('admin_post_cdra_save',static function(){try{
  [$id,$status,$priority,$hash]=cdra_editorial_authorized(wp_unslash($_POST),isset($_POST['_wpnonce'])?wp_unslash($_POST['_wpnonce']):'');
  (new CDRA_Store())->editorial($id,$status,$priority,get_current_user_id(),$hash);wp_safe_redirect(admin_url('admin.php?page=cyberdat-research&updated=1'));exit;
 }catch(Throwable $error){wp_die(esc_html($error instanceof CDRA_Error?$error->getMessage():'Research update failed.'),'Research Queue',['response'=>400]);}});
 add_action('admin_post_cdra_sync',static function(){try{
  cdra_need(cdra_staging()&&current_user_can('manage_options'),'manual_forbidden');check_admin_referer('cdra_sync');$source=sanitize_key(wp_unslash($_POST['source']??''));cdra_need(isset(cdra_sources()[$source]),'source_not_allowed');$s=new CDRA_Store();$s->mutate('manual_queue',static function($queue)use($source){$queue=is_array($queue)?$queue:[];$queue[$source]=$queue[$source]??['requested'=>time(),'actor'=>get_current_user_id()];return $queue;});wp_safe_redirect(admin_url('admin.php?page=cyberdat-research&queued=1'));exit;
 }catch(Throwable $error){wp_die('Research request rejected.','Research Queue',['response'=>400]);}});
}
function cdra_admin_query($filters){
 $s=new CDRA_Store();$where=['1=1'];$params=[];
 foreach(['source','status','severity'] as $field){$v=$filters[$field]??'';if($v===''){continue;}
  $allowed=$field==='source'?array_keys(cdra_sources()):($field==='status'?array_keys(cdra_statuses()):['Critical','High','Medium','Low','Unclassified','Not rated']);cdra_need(in_array($v,$allowed,true),'invalid_filter');
  $column=$field==='status'?'editorial_status':$field;$where[]="i.$column=%s";$params[]=$v;
 }
 if(!empty($filters['date'])){$date=$filters['date'];$d=DateTimeImmutable::createFromFormat('!Y-m-d',$date,new DateTimeZone('UTC'));cdra_need($d&&$d->format('Y-m-d')===$date,'invalid_date_filter');$where[]='i.source_updated >= %s';$params[]=$date.' 00:00:00';}
 if(!empty($filters['cve'])){cdra_need(cdra_nvd_id($filters['cve']),'invalid_cve_filter');$where[]="EXISTS (SELECT 1 FROM {$s->prefix}cves c WHERE c.item_id=i.id AND c.cve=%s)";$params[]=$filters['cve'];}
 $sql="SELECT i.* FROM {$s->prefix}items i WHERE ".implode(' AND ',$where).' ORDER BY COALESCE(i.manual_priority,i.priority) DESC,i.source_updated DESC,i.id DESC LIMIT 25 OFFSET %d';$params[]=max(0,min(10000,((int)($filters['paged']??1)-1)*25));
 return $s->db->get_results($s->db->prepare($sql,...$params),ARRAY_A);
}
function cdra_admin_page(){
 if(cdra_staging()&&current_user_can('manage_options')&&function_exists('cdra_discovery_queue_page')&&(new CDRA_Store())->get('discovery_schema')===1){try{cdra_discovery_queue_page();}catch(Throwable $e){wp_die('Research queue unavailable or filter invalid.','Research',['response'=>400]);}return;}
 if(!cdra_staging()||!current_user_can('manage_options')){wp_die('Access denied.');}
 echo '<div class="wrap"><h1>'.esc_html__('Research Queue','cyberdat-research').'</h1><p>'.esc_html__('Official-source evidence and explainable editorial heuristics, not EPSS. Approved for Draft never publishes a post.','cyberdat-research').'</p>';
 try{
  $s=new CDRA_Store();$filters=[];foreach(['source','status','severity','date','cve','paged'] as $key){$filters[$key]=sanitize_text_field(wp_unslash($_GET[$key]??''));}
  echo '<form method="get"><input type="hidden" name="page" value="cyberdat-research">';
  foreach(['source'=>array_combine(array_keys(cdra_sources()),array_column(cdra_sources(),'name')),'status'=>cdra_statuses(),'severity'=>array_combine(['Critical','High','Medium','Low','Unclassified','Not rated'],['Critical','High','Medium','Low','Unclassified','Not rated'])] as $key=>$options){echo '<label>'.esc_html(ucfirst($key)).' <select name="'.esc_attr($key).'"><option value="">'.esc_html__('All','cyberdat-research').'</option>';foreach($options as $value=>$label){echo '<option value="'.esc_attr($value).'" '.selected($filters[$key],$value,false).'>'.esc_html($label).'</option>';}echo '</select></label> ';}
  echo '<label>'.esc_html__('Updated since','cyberdat-research').' <input type="date" name="date" value="'.esc_attr($filters['date']).'"></label> <label>CVE <input name="cve" value="'.esc_attr($filters['cve']).'" placeholder="CVE-2026-12345"></label> <button class="button">'.esc_html__('Filter','cyberdat-research').'</button></form>';
  echo '<h2>'.esc_html__('Source health','cyberdat-research').'</h2><ul>';
  foreach(cdra_sources() as $id=>$spec){$health=$s->get('health:'.$id,[]);$at=$health['last_success']??0;$status=!empty($health['last_error'])?'Sync Error':($at&&time()-$at<=$spec['fresh']?'Fresh':'Stale');echo '<li>'.esc_html($spec['name'].' · '.$status.' · Last Successful Sync: '.($at?gmdate('Y-m-d H:i:s',$at).' UTC':'Never').' · Last error: '.($health['last_error']??'').' · Scope: '.($health['coverage']??'source-specific')).'</li>';}
  echo '</ul>';if(cyberdat_research_active()){cyberdat_research_status_html();}
  echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'"><input type="hidden" name="action" value="cdra_sync">';wp_nonce_field('cdra_sync');echo '<label>'.esc_html__('Queue a bounded manual sync','cyberdat-research').' <select name="source">';foreach(cdra_sources() as $id=>$spec){echo '<option value="'.esc_attr($id).'">'.esc_html($spec['name']).'</option>';}echo '</select></label> <button class="button">'.esc_html__('Request sync','cyberdat-research').'</button><p>'.esc_html__('The server dispatcher handles one bounded job. Cooldown and API backoff cannot be bypassed here.','cyberdat-research').'</p></form>';
  echo '<p>'.esc_html(sprintf(__('Indexed research items: %d','cyberdat-research'),$s->count())).'</p><table class="widefat striped"><thead><tr><th>Evidence</th><th>Priority</th><th>CVE / KEV</th><th>Editorial review</th></tr></thead><tbody>';
  foreach(cdra_admin_query($filters) as $row){$record=json_decode($row['payload'],true,64,JSON_THROW_ON_ERROR);$reasons=json_decode($row['reasons'],true);$effective=$row['manual_priority']??$row['priority'];$kev=$s->kev($record['cve_ids']);
   echo '<tr><td><a href="'.esc_url($record['canonical_url']).'" target="_blank" rel="noopener noreferrer">'.esc_html($record['original_title']).'</a><br>'.esc_html($record['source_name'].' · '.$record['source_updated']).'<details><summary>'.esc_html__('Source summary and metadata','cyberdat-research').'</summary><p>'.esc_html($record['summary']).'</p><p>'.esc_html('CVSS '.($record['assessment']['version']??'Not rated').' · '.($record['assessment']['score']??'—').' · '.($record['assessment']['source']??'—')).'</p>';
   if(!empty($record['cisa_original'])){foreach(['dateAdded','dueDate','requiredAction','knownRansomwareCampaignUse','notes'] as $key){echo '<p>'.esc_html($key.': '.($record['cisa_original'][$key]??'Not provided')).'</p>';}}
   foreach($record['references'] as $reference){echo '<p><a href="'.esc_url($reference).'" target="_blank" rel="noopener noreferrer">'.esc_html($reference).'</a></p>';}echo '</details></td><td>'.esc_html($effective.($row['manual_priority']!==null?' (manual)':' (heuristic)')).'<details><summary>'.esc_html__('Why this priority?','cyberdat-research').'</summary><ul>';
   foreach(($reasons['reasons']??[]) as $reason){echo '<li>'.esc_html($reason['points'].' · '.$reason['explanation']).'</li>';}echo '</ul></details></td><td>'.esc_html(implode(', ',$record['cve_ids'])).'<br>'.esc_html($kev?'Confirmed in current KEV':'No confirmed current KEV relationship').'</td><td><form method="post" action="'.esc_url(admin_url('admin-post.php')).'"><input type="hidden" name="action" value="cdra_save"><input type="hidden" name="item_id" value="'.esc_attr($row['id']).'"><input type="hidden" name="content_hash" value="'.esc_attr($row['content_hash']).'">';wp_nonce_field('cdra_item_'.$row['id']);
   echo '<label>'.esc_html__('Status','cyberdat-research').' <select name="status">';foreach(cdra_statuses() as $key=>$label){echo '<option value="'.esc_attr($key).'" '.selected($row['editorial_status'],$key,false).'>'.esc_html($label).'</option>';}echo '</select></label><br><label>'.esc_html__('Manual priority (blank = automatic)','cyberdat-research').' <input type="number" name="priority" min="0" max="100" value="'.esc_attr($row['manual_priority']??'').'"></label><br><button class="button">'.esc_html__('Save review','cyberdat-research').'</button></form></td></tr>';
  }
  echo '</tbody></table>'; $page=max(1,(int)($filters['paged']?:1));foreach(['Previous'=>max(1,$page-1),'Next'=>$page+1] as $label=>$number){echo '<a class="button" href="'.esc_url(add_query_arg(array_merge(['page'=>'cyberdat-research'],$filters,['paged'=>$number]),admin_url('admin.php'))).'">'.esc_html($label).'</a> ';}
 }catch(Throwable $error){echo '<div class="notice notice-error"><p>'.esc_html__('Research data is unavailable or a filter is invalid. No data was changed.','cyberdat-research').'</p></div>';}
 echo '</div>';
}
