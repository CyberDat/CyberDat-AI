<?php
/** Cached CISA KEV presentation. Never performs a network request. */
defined('ABSPATH') || exit;
if(function_exists('cyberdat_research_dashboard') && cyberdat_research_active()){get_template_part('template-parts/home/threat-dashboard');return;}
$view=cyberdat_kev_view();$cache=$view['cache'];$metrics=$view['metrics'];
$snapshot=$cache && $cache['snapshot'];
$mode=$snapshot?__('OFFICIAL SNAPSHOT · NOT LIVE','cyberdat'):__('CISA KEV · CACHED DATA','cyberdat');
$source='https://www.cisa.gov/known-exploited-vulnerabilities-catalog';
$rows=$cache?array_slice($cache['catalog']['vulnerabilities'],0,3):[];
?>
<section class="intel-section" aria-labelledby="intel-heading" data-kev-status="<?php echo esc_attr($view['status']); ?>">
 <div class="section-heading-row"><div><p class="eyebrow">SIGNAL / CONTEXT / ACTION</p><h2 id="intel-heading"><?php esc_html_e('Threat Intelligence Dashboard','cyberdat'); ?></h2></div><span class="sample-label"><?php echo esc_html($mode); ?></span></div>
 <div class="intel-shell"><div class="intel-toolbar"><span class="terminal-mark" aria-hidden="true">&gt;_</span><span>CYBERDAT / THREAT OBSERVATORY</span><span class="offline-badge"><?php echo esc_html($view['status']); ?></span></div>
 <?php if(function_exists('cyberdat_research_active') && cyberdat_research_active()){cyberdat_research_status_html();} ?>
 <div class="intel-metrics">
 <?php foreach ([
  [__('KEV catalog entries','cyberdat'),$metrics?$metrics['total']:null,__('Known exploited vulnerabilities','cyberdat'),'mint'],
  [__('Added in 7 days','cyberdat'),$metrics?$metrics['seven']:null,__('By dateAdded · UTC calendar days','cyberdat'),'coral'],
  [__('Added in 30 days','cyberdat'),$metrics?$metrics['thirty']:null,__('By dateAdded · UTC calendar days','cyberdat'),'amber'],
  [__('Ransomware-linked KEVs','cyberdat'),$metrics?$metrics['ransomware']:null,__('CISA ransomware use field: Known','cyberdat'),'blue'],
 ] as $metric): ?>
 <div class="intel-metric"><span><?php echo esc_html($metric[0]); ?></span><strong class="metric-<?php echo esc_attr($metric[3]); ?>"><?php echo esc_html($metric[1]===null?'—':number_format_i18n($metric[1])); ?></strong><small><?php echo esc_html($metric[2]); ?></small></div>
 <?php endforeach; ?></div>
 <div class="intel-panels"><div class="signal-chart"><div class="panel-heading"><h3><?php esc_html_e('KEV additions by day','cyberdat'); ?></h3><span><?php esc_html_e('7 UTC CALENDAR DAYS','cyberdat'); ?></span></div>
 <?php if($metrics):
 $days=$metrics['days'];$max=max(1,max($days));$points=[];$labels=[];$i=0;
 foreach($days as $date=>$count){$x=30+84*$i;$y=140-112*$count/$max;$points[]=sprintf('%d %.2f',$x,$y);$labels[]=[$x,$date,$count];++$i;}
 $path='M'.implode('L',$points);
 $description=implode('; ',array_map(static function($row){return $row[1].': '.$row[2];},$labels));
 ?>
 <svg class="activity-svg" viewBox="0 0 560 170" role="img" aria-labelledby="signal-title signal-desc"><title id="signal-title"><?php esc_html_e('CISA KEV additions by dateAdded','cyberdat'); ?></title><desc id="signal-desc"><?php echo esc_html($description); ?></desc><defs><linearGradient id="signal-fill" x1="0" y1="0" x2="0" y2="1"><stop stop-color="#70f3cb" stop-opacity=".24"/><stop offset="1" stop-color="#70f3cb" stop-opacity="0"/></linearGradient></defs><g stroke="#293746" stroke-width="1"><path d="M30 20H535M30 60H535M30 100H535M30 140H535"/></g><path d="<?php echo esc_attr($path.'L534 140H30Z'); ?>" fill="url(#signal-fill)"/><path d="<?php echo esc_attr($path); ?>" fill="none" stroke="#70f3cb" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/><g fill="#70f3cb"><?php foreach($labels as $i=>$label): ?><circle cx="<?php echo esc_attr($label[0]); ?>" cy="<?php echo esc_attr(sprintf('%.2f',140-112*$label[2]/$max)); ?>" r="3"/><?php endforeach; ?></g><g fill="#a6b5c4" font-size="10" font-family="monospace"><?php foreach($labels as $label): ?><text x="<?php echo esc_attr($label[0]-16); ?>" y="163"><?php echo esc_html(substr($label[1],5)); ?></text><?php endforeach; ?></g></svg>
 <?php else: ?><p class="chart-caption"><?php esc_html_e('Verified CISA KEV data is unavailable. No estimated values are shown.','cyberdat'); ?></p><?php endif; ?>
 <p class="chart-caption"><?php echo esc_html($metrics?sprintf(/* translators: %s: UTC reference date. */__('Reference date: %s UTC. Counts are catalog additions, not attacks or incidents.','cyberdat'),gmdate('Y-m-d',$view['reference'])):__('No successful import yet.','cyberdat')); ?></p></div>
<?php get_template_part('template-parts/home/nvd-severity'); ?></div>
 <div class="vulnerability-panel"><div class="panel-heading"><h3><?php esc_html_e('Latest KEV additions','cyberdat'); ?></h3><span><?php esc_html_e('CISA KEV · dateAdded DESC, CVE ID DESC','cyberdat'); ?></span></div><div class="vulnerability-scroll" role="region" aria-label="<?php esc_attr_e('Latest CISA KEV additions','cyberdat'); ?>" tabindex="0"><table class="vulnerability-table"><thead><tr><th scope="col">CVE ID</th><th scope="col">VENDOR / PRODUCT</th><th scope="col">ADDED TO KEV</th><th scope="col">CVSS / SEVERITY</th><th scope="col">RANSOMWARE USE</th><th scope="col">SOURCE</th></tr></thead><tbody>
 <?php foreach($rows as $row): ?>
 <tr><td><code><?php echo esc_html($row['cveID']); ?></code></td><td style="overflow-wrap:anywhere"><?php echo esc_html($row['vendorProject'].' / '.$row['product']); ?></td><td><time datetime="<?php echo esc_attr($row['dateAdded']); ?>"><?php echo esc_html($row['dateAdded']); ?></time></td><td style="max-width:240px;overflow-wrap:anywhere"><?php get_template_part('template-parts/home/nvd-cell',null,['id'=>$row['cveID']]); ?></td><td><span class="table-status"><?php echo esc_html($row['knownRansomwareCampaignUse']); ?></span></td><td><a href="<?php echo esc_url($source); ?>" aria-label="<?php echo esc_attr(sprintf(/* translators: %s: CVE identifier. */__('CISA KEV catalog source for %s','cyberdat'),$row['cveID'])); ?>">CISA KEV ↗</a></td></tr>
 <?php endforeach; ?>
 <?php if(!$rows): ?><tr><td colspan="6"><?php echo esc_html($cache?__('No KEV entries in the verified catalog.','cyberdat'):__('Verified CISA KEV data is unavailable.','cyberdat')); ?></td></tr><?php endif; ?>
 </tbody></table></div></div>
 <div class="intel-footer"><span><?php if($cache): ?><?php echo esc_html($snapshot?__('Fixed official snapshot — not live.','cyberdat'):__('Last received validated dataset:','cyberdat')); ?> <time datetime="<?php echo esc_attr(gmdate(DATE_W3C,$cache['fetched_at'])); ?>"><?php echo esc_html(gmdate('Y-m-d H:i',$cache['fetched_at']).' UTC'); ?></time><br><?php echo esc_html(sprintf(/* translators: %s: Catalog release timestamp. */__('Catalog released: %s','cyberdat'),$cache['catalog']['dateReleased'])); ?><?php else: ?><?php esc_html_e('No verified cache. Background updates are disabled in this preview.','cyberdat'); ?><?php endif; ?> <br><?php esc_html_e('Unknown ransomware use does not mean no ransomware use.','cyberdat'); ?></span><a href="<?php echo esc_url($cache?$cache['source']:cyberdat_kev_sources()[0]); ?>"><?php esc_html_e('Source: CISA KEV JSON','cyberdat'); ?> ↗</a></div></div>
</section>
