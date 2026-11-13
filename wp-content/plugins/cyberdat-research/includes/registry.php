<?php
defined('ABSPATH') || exit;
class CDRA_Error extends RuntimeException {public $retry;public $diagnostic;public function __construct($code,$retry=0,$diagnostic=[]){parent::__construct($code);$this->retry=(int)$retry;$this->diagnostic=$diagnostic;}}
function cdra_need($ok,$code){if(!$ok){throw new CDRA_Error($code);}}
function cdra_sources(){return [
 'kev'=>['name'=>'CISA KEV','url'=>'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json','format'=>'json','interval'=>21600,'fresh'=>28800,'hosts'=>['www.cisa.gov']],
 'nvd'=>['name'=>'NIST NVD','url'=>'https://services.nvd.nist.gov/rest/json/cves/2.0','format'=>'json','interval'=>7200,'fresh'=>14400,'hosts'=>['nvd.nist.gov','services.nvd.nist.gov']],
 'cisa-advisories'=>['name'=>'CISA Cybersecurity Advisories','url'=>'https://www.cisa.gov/cybersecurity-advisories/all.xml','format'=>'rss','interval'=>21600,'fresh'=>28800,'hosts'=>['www.cisa.gov']],
 'cert-eu'=>['name'=>'CERT-EU Security Advisories','url'=>'https://cert.europa.eu/publications/security-advisories-rss','format'=>'rss','interval'=>21600,'fresh'=>28800,'hosts'=>['cert.europa.eu']],
 'msrc'=>['name'=>'Microsoft Security Response Center','url'=>'https://api.msrc.microsoft.com/update-guide/rss','format'=>'rss','interval'=>21600,'fresh'=>28800,'hosts'=>['msrc.microsoft.com','api.msrc.microsoft.com','www.microsoft.com','msrc-blog.microsoft.com']],
];}
function cdra_statuses(){return ['new'=>'New','under_review'=>'Reviewed','approved_for_draft'=>'Selected','ready_for_content_agent'=>'Ready for Content Agent','rejected'=>'Rejected','archived'=>'Archived'];}
function cdra_json($value){$json=wp_json_encode($value,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);cdra_need(is_string($json),'json_encode');return $json;}
function cdra_stamp($at=null){return gmdate('Y-m-d H:i:s',$at??time());}
function cdra_time($value){
 cdra_need(is_string($value)&&preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z?$/D',$value),'invalid_timestamp');
 $date=DateTimeImmutable::createFromFormat('!Y-m-d\TH:i:s',substr($value,0,19),new DateTimeZone('UTC'));
 cdra_need($date && $date->format('Y-m-d\TH:i:s')===substr($value,0,19),'invalid_timestamp');return $date->getTimestamp();
}

function cdra_hash($value){$sort=static function($item)use(&$sort){if(!is_array($item)){return $item;}if(!array_is_list($item)){ksort($item,SORT_STRING);}foreach($item as $key=>$child){$item[$key]=$sort($child);}return $item;};return hash('sha256',cdra_json($sort($value)));}

/** Only indivisible time slices may use NVD's larger single-response envelope. */
function cdra_nvd_page_cap($query){if(isset($query['lastModStartDate'],$query['lastModEndDate'])&&!isset($query['cveIds'])&&($query['startIndex']??0)===0){$span=cdra_time($query['lastModEndDate'])-cdra_time($query['lastModStartDate']);if($span>=0&&$span<=1){return 2000;}}return 200;}
