<?php
/** Offline fixed-fixture tests. No database, network, WordPress bootstrap or posts. */
define('ABSPATH','/var/www/cyberdat-staging/public/');define('DB_NAME','cyberdat_staging');
class WP_Error {public function __construct(public $code,public $message=''){} }
function is_wp_error($v){return $v instanceof WP_Error;}
function wp_json_encode($v,$flags=0){return json_encode($v,$flags);}
function wp_parse_url($s,$component=-1){return parse_url($s,$component);}
function wp_strip_all_tags($s){return strip_tags($s);}
function wp_get_environment_type(){return $GLOBALS['environment']??'staging';}
function get_option($k,$default=null){return $k==='home'?'https://staging.cyberdat.eu':$default;}
function current_user_can(...$args){return $GLOBALS['cap']??false;}
function wp_verify_nonce(...$args){return $GLOBALS['nonce']??false;}
function add_action(...$args){}
function add_filter(...$args){}
function register_activation_hook(...$args){}
require __DIR__.'/../wp-content/plugins/cyberdat-research/cyberdat-research.php';
$fixture=json_decode(file_get_contents(CDRA_DIR.'/tests/fixtures.json'),true);
function check($ok,$name){if(!$ok){throw new RuntimeException($name);}echo "PASS: $name\n";}
function rejected($callback,$name){try{$callback();}catch(Throwable $e){check($e instanceof CDRA_Error||$e instanceof JsonException,$name);return;}throw new RuntimeException('Not rejected: '.$name);}
$kev=cdra_kev(cdra_json($fixture['kev']));check(count($kev['rows'])===1,'valid complete KEV fixture');
foreach(['shortDescription','requiredAction','dueDate','notes','knownRansomwareCampaignUse'] as $key){check($kev['rows'][0]['cisa_original'][$key]===$fixture['kev']['vulnerabilities'][0][$key],'CISA original preserved '.$key);}
rejected(static fn()=>cdra_kev('{'),'invalid JSON rejected');
$empty=$fixture['kev'];$empty['vulnerabilities']=[];$empty['count']=0;rejected(static fn()=>cdra_kev(cdra_json($empty)),'empty catalog rejected');
$partial=$fixture['kev'];unset($partial['vulnerabilities'][0]['requiredAction']);rejected(static fn()=>cdra_kev(cdra_json($partial)),'partial KEV row rejected');
$duplicate=$fixture['kev'];$duplicate['count']=2;$duplicate['vulnerabilities'][]=$duplicate['vulnerabilities'][0];rejected(static fn()=>cdra_kev(cdra_json($duplicate)),'duplicate CISA ID rejected');
$page=cdra_nvd_page(cdra_json($fixture['nvd']),['startIndex'=>0]);check($page['rows'][0]['assessment']['version']==='3.1'&&$page['rows'][0]['assessment']['score']==9.8,'CVSS 3.1 score/version/source retained');
check($page['rows'][0]['cwe']===['CWE-119']&&count($page['rows'][0]['references'])===1,'CWE and references retained');
foreach(['4.0'=>'cvssMetricV40','3.0'=>'cvssMetricV30','2.0'=>'cvssMetricV2'] as $version=>$key){$body=$fixture['nvd'];$metric=$body['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0];$metric['cvssData']['version']=$version;$metric['cvssData']['vectorString']=$version==='2.0'?'AV:N/AC:L/Au:N/C:P/I:P/A:P':'CVSS:'.$version.'/AV:N/AC:L';if($version==='2.0'){$metric['baseSeverity']='HIGH';unset($metric['cvssData']['baseSeverity']);$metric['cvssData']['baseScore']=7.5;}$body['vulnerabilities'][0]['cve']['metrics']=[$key=>[$metric]];$r=cdra_nvd_page(cdra_json($body),['startIndex'=>0]);check($r['rows'][0]['assessment']['version']===$version,'CVSS version distinct '.$version);}
$zero=$fixture['nvd'];$zero['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']=0;$zero['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']='NONE';$z=cdra_nvd_page(cdra_json($zero),['startIndex'=>0]);check($z['rows'][0]['assessment']['source_severity']==='NONE'&&$z['rows'][0]['assessment']['severity']==='None','explicit source NONE is preserved, distinct from missing severity');
$unrated=$fixture['nvd'];$unrated['vulnerabilities'][0]['cve']['metrics']=[];$r=cdra_nvd_page(cdra_json($unrated),['startIndex'=>0]);check($r['rows'][0]['assessment']===null,'absent CVSS never invented');
$bad=$fixture['nvd'];$bad['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']=99;rejected(static fn()=>cdra_nvd_page(cdra_json($bad),['startIndex'=>0]),'invalid CVSS rejected');
$bad=$fixture['nvd'];$bad['startIndex']=1;rejected(static fn()=>cdra_nvd_page(cdra_json($bad),['startIndex'=>0]),'unexpected pagination rejected');
rejected(static fn()=>cdra_query('nvd',['resultsPerPage'=>2000,'startIndex'=>0,'lastModStartDate'=>'2020-01-01T00:00:00Z','lastModEndDate'=>'2020-01-02T00:00:00Z']),'oversized page request denied');
rejected(static fn()=>cdra_query('nvd',['resultsPerPage'=>50,'startIndex'=>0,'url'=>'http://127.0.0.1']),'arbitrary URL/query denied');
rejected(static fn()=>cdra_query('evil',[]),'unregistered endpoint denied');
foreach(['127.0.0.1','10.0.0.1','169.254.169.254','100.100.100.200','192.168.1.1','::1','fe80::1','::ffff:127.0.0.1','2001:db8::1'] as $ip){check(!cdra_public_ip($ip),'SSRF IP denied '.$ip);}check(cdra_public_ip('1.1.1.1'),'public address validation');
$xml='<?xml version="1.0"?><rss><channel><item><guid>test-1</guid><title>TEST advisory CVE-2020-0001</title><link>https://cert.europa.eu/publications/security-advisories/test</link><description>TEST synthetic RSS fixture only</description><pubDate>Wed, 01 Jan 2020 12:00:00 GMT</pubDate></item></channel></rss>';
check(count(cdra_feed($xml,'cert-eu'))===1,'official-host RSS normalized');
rejected(static fn()=>cdra_feed('<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>'.$xml,'cert-eu'),'XXE and DTD denied');
rejected(static fn()=>cdra_feed('<rss><channel/></rss>','cert-eu'),'empty feed denied');
check(cdra_url('https://cert.europa.eu/advisory?a=1&utm_source=x#fragment')==='https://cert.europa.eu/advisory?a=1','canonical tracking/fragment normalization');
$priority=cdra_priority($page['rows'][0],true,false,strtotime('2020-01-01 12:00 UTC'));check($priority['score']>cdra_priority($page['rows'][0],false,false,strtotime('2020-01-01 12:00 UTC'))['score']&&count($priority['reasons'])>=3,'KEV priority with explicit reasons');
check($priority['kind']==='editorial_heuristic_not_EPSS','priority is not EPSS');
$input=['item_id'=>'1','status'=>'approved_for_draft','priority'=>'77','content_hash'=>str_repeat('a',64)];
rejected(static fn()=>cdra_editorial_authorized($input,'nonce'),'unauthorized status action denied');$GLOBALS['cap']=true;rejected(static fn()=>cdra_editorial_authorized($input,'nonce'),'invalid nonce denied');$GLOBALS['nonce']=true;check(cdra_editorial_authorized($input,'nonce')[1]==='approved_for_draft','authorized nonced review input');
$input['status']='publish';rejected(static fn()=>cdra_editorial_input($input),'Published is not an editorial status');
check(count(cdra_statuses())===4,'four required editorial statuses');
$GLOBALS['environment']='production';check(!cdra_staging(),'production environment refused');
foreach(glob(CDRA_DIR.'/includes/*.php') as $file){check(!preg_match('/\b(?:wp_insert_post|wp_publish_post)\s*\(/',file_get_contents($file)),'no automatic publication in '.basename($file));}
echo "PASS: offline Research Agent tests; no live calls, DB changes or posts\n";
