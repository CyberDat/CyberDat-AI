<?php
/** No WordPress, network, database or cache mutations. */
define('ABSPATH',__DIR__.'/');
function cdra_staging(){return true;}
function cdra_sources(){return ['nvd'=>['fresh'=>14400],'kev'=>['fresh'=>28800]];}
class CDRA_Store {function get($key,$default=null){if($key==='live_enabled'){return true;}return $GLOBALS['fixture'];}}
function esc_html($s){return htmlspecialchars((string)$s,ENT_QUOTES,'UTF-8');}function esc_attr($s){return esc_html($s);}function __($s,...$a){return $s;}function esc_html_e($s,...$a){echo esc_html($s);}function number_format_i18n($n){return number_format($n);}
$GLOBALS['fixture']=['schema'=>2,'sources'=>['nvd'=>['last_success'=>1000]],'nvd_last_incremental_success'=>1000,'kev'=>['catalog'=>['count'=>1769]],'indexed_cves'=>53,'nvd'=>[]];
foreach(['CVE-2020-0001','CVE-2020-0002','CVE-2020-0003'] as $id){$GLOBALS['fixture']['nvd'][$id]=['record'=>['assessment'=>['severity'=>'High']],'checked_at'=>1000];}
require __DIR__.'/../wp-content/plugins/cyberdat-research/includes/dashboard.php';
function cyberdat_nvd_coverage(){return cyberdat_research_coverage();}
$c=cyberdat_nvd_coverage();if($c['indexed_cves']!==53||$c['loaded']!==3||array_sum($c['counts'])!==3){throw new RuntimeException('Wrong coverage scope');}
ob_start();require __DIR__.'/../wp-content/themes/cyberdat/template-parts/home/nvd-severity.php';$html=ob_get_clean();
foreach(['data-nvd-indexed="53"','data-nvd-loaded="3"','data-nvd-scope="kev-intersection"','KEV MATCHES','Total synchronized NVD CVEs: 53','Full CISA KEV catalog: 1769','This chart: 3 KEV-linked CVEs'] as $expected){if(!str_contains($html,$expected)){throw new RuntimeException('Missing scope label: '.$expected);}}
echo "PASS: chart distinguishes 3 matched CVEs, 53 indexed NVD CVEs and 1769 KEV entries\n";
echo "PASS: no source queries, cache clears, jobs or imports executed\n";
