<?php
defined('ABSPATH') || exit;
function cdca_worker_config(){
 $path='/var/lib/cyberdat-staging/content/worker.json';if(!cdca_stage()||!is_readable($path)||is_link($path)){return null;}$v=json_decode(file_get_contents($path),true,16);return is_array($v)&&($v['enabled']??false)===true&&($v['mode']??'')==='mock_only'?$v:null;
}
function cdca_worker_permission($request){
 $config=cdca_worker_config();$id=$request->get_header('x-cyberdat-worker-id');$token=$request->get_header('x-cyberdat-worker-token');
 if(!is_ssl()||!$config||!is_string($id)||!preg_match('/^[a-z0-9-]{1,32}$/D',$id)||!is_string($token)||!preg_match('/^[a-f0-9]{64}$/D',$token)||!isset($config['workers'][$id])||!hash_equals($config['workers'][$id],hash('sha256',$token))){return new WP_Error('content_worker_forbidden','Private worker access denied.',['status'=>403]);}
 return true;
}
function cdca_worker_dispatch($request){
 try{
  cdca_need(cdca_stage(),'staging_only');$raw=$request->get_body();cdca_need(strlen($raw)<=65000,'request_size');$data=json_decode($raw,true,32,JSON_THROW_ON_ERROR);cdca_need(is_array($data)&&isset($data['action'])&&is_string($data['action']),'worker_action');$worker=$request->get_header('x-cyberdat-worker-id');$s=new CDCA_Store();$s->rate($worker);$action=$data['action'];$keys=array_keys($data);sort($keys);$allowed=['claim'=>['action'],'heartbeat'=>['action','id','lease'],'fail'=>['action','code','id','lease'],'complete'=>['action','document','id','lease','submission']];cdca_need(isset($allowed[$action])&&$keys===$allowed[$action],'request_fields');
  if($action==='claim'){$result=['job'=>$s->claim($worker),'mode'=>'mock_only'];}
  else{cdca_need(is_int($data['id'])&&$data['id']>0&&is_string($data['lease']),'worker_identity');$id=$data['id'];$lease=$data['lease'];
   if($action==='heartbeat'){$result=$s->heartbeat($id,$worker,$lease);}
   elseif($action==='fail'){$result=$s->fail($id,$worker,$lease,$data['code']);}
   else{$result=$s->complete($id,$worker,$lease,$data['submission'],$data['document']);}
  }
  return new WP_REST_Response($result,200,['Cache-Control'=>'no-store','X-Robots-Tag'=>'noindex, nofollow']);
 }catch(Throwable $e){$code=$e instanceof CDCA_Error?$e->getMessage():'content_processing';$status=$code==='worker_rate_limit'?429:409;return new WP_REST_Response(['code'=>$code,'retryable'=>in_array($code,['worker_rate_limit','content_database','selection_busy'],true)],$status,['Cache-Control'=>'no-store','Retry-After'=>'60']);}
}
function cdca_routes(){register_rest_route('cyberdat-content/v1','/worker',['methods'=>'POST','permission_callback'=>'cdca_worker_permission','callback'=>'cdca_worker_dispatch']);}
