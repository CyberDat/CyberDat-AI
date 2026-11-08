<?php
/** Offline analytics, rendering, filter safety and mixed-CVSS coverage tests. */
define('ABSPATH','fixture');
function wp_json_encode($value,$flags=0){return json_encode($value,$flags);}
require __DIR__.'/../wp-content/plugins/cyberdat-research/includes/registry.php';
eval(substr(str_replace('function cyberdat_research_dashboard()', 'function fixture_runtime_provider()',file_get_contents(__DIR__.'/../wp-content/plugins/cyberdat-research/includes/analytics.php')),5));
function check($ok,$message){if(!$ok){throw new RuntimeException($message);}echo "PASS: $message\n";}
$now=strtotime('2026-11-08T18:00:00Z');$rows=[];
function row($source,$id,$score,$version,$date='2026-11-08 12:00:00'){
 return ['source'=>$source,'source_id'=>$id,'canonical_url'=>'https://nvd.nist.gov/vuln/detail/'.$id,'published'=>$date,'source_updated'=>'2026-11-08 13:00:00','kev_confirmed'=>$id==='CVE-2020-0001'?1:0,'title'=>'<script>TEST untrusted title</script>','summary'=>'TEST <img src=x onerror=alert(1)>','cve_ids'=>[$id],'assessment'=>$score===null?null:['score'=>$score,'version'=>$version,'source'=>'test@example.org']];
}
$rows[] =row('nvd','CVE-2020-0001',9.8,'3.1');$rows[]=row('nvd','CVE-2020-0002',7.5,'2.0');$rows[]=row('nvd','CVE-2020-0003',null,null);$rows[]=row('nvd','CVE-2020-0004',0,'4.0','2020-01-01 00:00:00');$rows[]=row('cert-eu','TEST-advisory',null,null);
$catalog=['catalogVersion'=>'TEST','dateReleased'=>'2026-11-06T00:00:00Z','vulnerabilities'=>[['cveID'=>'CVE-2020-0001','dateAdded'=>'2026-11-06','knownRansomwareCampaignUse'=>'Known']]];
$state=['source_health'=>[],'origin'=>'2026-11-07T00:00:00Z','checkpoint'=>$now,'window'=>null,'completed'=>['verified_results'=>4],'backfill'=>['status'=>'not_requested'],'queue_total'=>5];
$m=cdra_dashboard_model($rows,$catalog,$state,$now);
check($m['counts']['nvd']===4&&$m['counts']['kev']===1&&$m['counts']['advisories']===1,'NVD, KEV and advisories remain separate real-record counts');
check($m['counts']['critical']===1&&$m['counts']['high']===1&&$m['counts']['rated']===3,'critical/high use actual selected score ranges; missing score not fabricated');
check($m['severity']['None']===1&&$m['severity']['Unrated']===1&&array_sum($m['severity'])===4,'zero score differs from absent CVSS and chart includes every indexed NVD CVE');
check($m['versions']['2.0']['High']===1&&$m['versions']['3.1']['Critical']===1,'CVSS versions retained and disaggregated');
check($m['counts']['nvd_7']===3&&$m['counts']['nvd_30']===3&&array_sum($m['days'])===3,'publication chronology uses source publication, not receipt or modification');
check($m['counts']['kev_nvd']===1&&$m['counts']['ransomware']===1,'KEV overlap and ransomware require confirmed fields');
check($m['feed'][0]['published']==='2026-11-08 12:00:00'&&$m['feed'][0]['summary']==='TEST <img src=x onerror=alert(1)>','source text remains data for escaped presentation');
$f=cdra_dashboard_filters(['ti_source'=>['nvd'],'ti_severity'=>'<script>','ti_kind'=>'advisory']);check($f===['ti_source'=>'all','ti_severity'=>'all','ti_kind'=>'advisory'],'filter arrays and injection rejected by exact allowlists');
check(count(cdra_dashboard_feed($m,$f))===1&&count(cdra_dashboard_feed($m,cdra_dashboard_filters(['ti_source'=>'nvd','ti_severity'=>'Critical'])))===1,'combined source/severity/type filters work without JavaScript');
for($i=0;$i<40;$i++){$rows[]=row('nvd','TEST-'.$i,5.5,'3.1');}$m2=cdra_dashboard_model($rows,$catalog,$state,$now);check(count(array_filter($m2['feed'],static fn($r)=>$r['source']==='nvd'))===20&&count(array_filter($m2['feed'],static fn($r)=>$r['kind']==='advisory'))===1&&$m2['counts']['nvd']===44,'bounded per-source feed does not truncate aggregate counts or crowd out advisories');
function cyberdat_research_dashboard(){return $GLOBALS['model'];}
function __($s,$domain=''){return $s;}function esc_html__($s,$d=''){return htmlspecialchars($s,ENT_QUOTES,'UTF-8');}function esc_html_e($s,$d=''){echo esc_html__($s);}function esc_html($s){return htmlspecialchars((string)$s,ENT_QUOTES,'UTF-8');}function esc_attr($s){return esc_html($s);}function esc_url($s){return esc_attr($s);}function cyberdat_intelligence_url(){return 'https://staging.cyberdat.eu/threat-intelligence/';}function home_url($s){return 'https://staging.cyberdat.eu'.$s;}function number_format_i18n($s){return number_format($s);}function selected($a,$b){if($a===$b){echo ' selected';}}
require_once __DIR__.'/../wp-content/themes/cyberdat/inc/intelligence-charts.php';
function get_template_part($part,$name=null,$args=[]){require __DIR__.'/../wp-content/themes/cyberdat/'.$part.'.php';}
$GLOBALS['model']=$m;$_GET=[];ob_start();require __DIR__.'/../wp-content/themes/cyberdat/template-parts/home/threat-dashboard.php';$html=ob_get_clean();
check(substr_count($html,'data-kpi=')===6,'six real source-labelled KPI cards rendered');
check(str_contains($html,'data-threat-dashboard="2.0"')&&str_contains($html,'Security Advisories')&&str_contains($html,'CVSS Not Available'),'new Dashboard and genuine missing-data presentation rendered');
check(!str_contains($html,'<script>TEST')&&!str_contains($html,'<img src=x')&&str_contains($html,'&lt;script&gt;'),'external titles and summaries safely escaped');
check(str_contains($html,'method="get"')&&str_contains($html,'name="ti_source"')&&!str_contains($html,'<script'),'server HTML filters require no JavaScript');
file_put_contents('/tmp/cyberdat-dashboard-fixture.html',$html);
check(count($m['chart_series']['kev'])===90&&count($m['chart_series']['nvd'])===90&&array_sum($m['chart_series']['kev'])===1&&array_sum($m['chart_series']['nvd'])===3,'90-day series uses source dates and does not import old CVEs into publication trends');
check(substr_count($html,'data-chart-id=')===6&&str_contains($html,'stroke-dasharray')&&str_contains($html,'data-period="90"'),'all six real-data charts and native SVG controls rendered');
echo "PASS: Dashboard offline tests; no network, database or production writes\n";
