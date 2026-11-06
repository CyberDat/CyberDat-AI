<?php
/** Visual prototype only: sample output must never appear outside Playground. */
defined( 'ABSPATH' ) || exit;
if ( ! defined( 'CYBERDAT_PLAYGROUND' ) || ! CYBERDAT_PLAYGROUND ) {
    require __DIR__ . '/index.php';
    return;
}
require_once __DIR__ . '/inc/home-prototype.php';
get_header();
$featured = get_page_by_path( 'identity-boundaries-for-ai-agents', OBJECT, 'post' );
?>
<div class="prototype-notice"><span class="sample-label">SAMPLE DATA</span><span><?php esc_html_e( 'Design preview · Stories, vulnerability IDs and metrics are fictional. No live feeds.', 'cyberdat' ); ?></span></div>
<div class="home-masthead"><div><p class="eyebrow"><?php esc_html_e( 'Independent cybersecurity intelligence', 'cyberdat' ); ?></p><h1><?php esc_html_e( 'Understand the threat.', 'cyberdat' ); ?><br><span><?php esc_html_e( 'Stay ahead of it.', 'cyberdat' ); ?></span></h1></div><p><?php esc_html_e( 'The stories that matter. The context behind them. The knowledge to build a more secure world.', 'cyberdat' ); ?></p></div>
<section class="editorial-lead" aria-labelledby="featured-heading">
 <article class="featured-story">
  <a class="featured-art" href="<?php echo esc_url( cyberdat_prototype_url( $featured ) ); ?>" tabindex="-1" aria-hidden="true"><img src="<?php echo esc_url( get_theme_file_uri( '/assets/images/agent-network.svg' ) ); ?>" width="1000" height="620" alt="" fetchpriority="high"><span class="art-caption">CYBERDAT RESEARCH / 001</span></a>
  <div class="featured-body"><div class="story-meta"><span class="section-kicker"><?php esc_html_e( 'Featured Story', 'cyberdat' ); ?></span><span class="sample-label">SAMPLE DATA</span></div><h2 id="featured-heading"><a href="<?php echo esc_url( cyberdat_prototype_url( $featured ) ); ?>"><?php esc_html_e( 'The next attack surface isn’t a device. It’s an AI agent.', 'cyberdat' ); ?></a></h2><p><?php esc_html_e( 'When software starts making decisions, identity becomes the perimeter. A closer look at the trust boundaries of agentic systems.', 'cyberdat' ); ?></p><div class="article-meta"><span>AI SECURITY</span><span aria-hidden="true">/</span><span>ANALYSIS</span><span aria-hidden="true">/</span><span><?php esc_html_e( '8 min read · demo', 'cyberdat' ); ?></span></div></div>
 </article>
 <aside class="news-rail" aria-labelledby="news-heading"><div class="section-topline"><h2 id="news-heading"><?php esc_html_e( 'The Briefing', 'cyberdat' ); ?></h2><span class="rail-label"><?php esc_html_e( 'Latest News', 'cyberdat' ); ?></span></div>
 <?php foreach ( [
 ['preview-security-briefing', '01', 'THREAT INTELLIGENCE', 'A new perspective on the signals hiding in everyday network traffic'],
 ['network-defense-preview', '02', 'NETWORK SECURITY', 'Why defenders are rethinking the edge of the enterprise'],
 ['preview-ai-briefing', '03', 'AI SECURITY', 'The security questions every AI deployment should answer'],
 ] as $item ) : $post_item = get_page_by_path( $item[0], OBJECT, 'post' ); ?>
 <article class="brief-item"><span class="brief-number"><?php echo esc_html( $item[1] ); ?></span><div><div class="story-meta"><span><?php echo esc_html( $item[2] ); ?></span><span class="sample-label">SAMPLE</span></div><h3><a href="<?php echo esc_url( cyberdat_prototype_url( $post_item ) ); ?>"><?php echo esc_html( $item[3] ); ?></a></h3><span class="brief-date"><?php esc_html_e( 'Preview edition · Fictional story', 'cyberdat' ); ?></span></div></article>
 <?php endforeach; ?>
 <a class="text-link rail-bottom" href="<?php echo esc_url( home_url( '/news/' ) ); ?>"><?php esc_html_e( 'All news', 'cyberdat' ); ?> <span aria-hidden="true">↗</span></a></aside>
</section>
<section class="intel-section" aria-labelledby="intel-heading">
 <div class="section-heading-row"><div><p class="eyebrow">SIGNAL / CONTEXT / ACTION</p><h2 id="intel-heading"><?php esc_html_e( 'Threat Intelligence Dashboard', 'cyberdat' ); ?></h2></div><span class="sample-label">SAMPLE DATA · OFFLINE SNAPSHOT</span></div>
 <div class="intel-shell"><div class="intel-toolbar"><span class="terminal-mark" aria-hidden="true">&gt;_</span><span>CYBERDAT / THREAT OBSERVATORY</span><span class="offline-badge"><?php esc_html_e( 'DEMO MODE', 'cyberdat' ); ?></span></div>
 <div class="intel-metrics">
 <?php foreach ( [['Signals observed', '128', 'Across the demo dataset', 'mint'], ['Critical findings', '06', 'Illustrative severity only', 'coral'], ['High-priority findings', '18', 'Fictional triage queue', 'amber'], ['Research clusters', '12', 'Sample intelligence groups', 'blue']] as $metric ) : ?>
 <div class="intel-metric"><span><?php echo esc_html( $metric[0] ); ?></span><strong class="metric-<?php echo esc_attr( $metric[3] ); ?>"><?php echo esc_html( $metric[1] ); ?></strong><small><?php echo esc_html( $metric[2] ); ?></small></div>
 <?php endforeach; ?></div>
 <div class="intel-panels"><div class="signal-chart"><div class="panel-heading"><h3><?php esc_html_e( 'Signal activity', 'cyberdat' ); ?></h3><span>7 DEMO PERIODS</span></div><svg class="activity-svg" viewBox="0 0 560 170" role="img" aria-labelledby="signal-title signal-desc"><title id="signal-title">Sample signal activity</title><desc id="signal-desc">Fictional values for periods D1 through D7: 18, 32, 24, 49, 38, 68, 54. Not real threat activity.</desc><defs><linearGradient id="signal-fill" x1="0" y1="0" x2="0" y2="1"><stop stop-color="#70f3cb" stop-opacity=".24"/><stop offset="1" stop-color="#70f3cb" stop-opacity="0"/></linearGradient></defs><g stroke="#293746" stroke-width="1"><path d="M30 20H535M30 60H535M30 100H535M30 140H535"/></g><path d="M30 125L114 99L198 113L282 69L366 88L450 28L534 54V140H30Z" fill="url(#signal-fill)"/><path d="M30 125L114 99L198 113L282 69L366 88L450 28L534 54" fill="none" stroke="#70f3cb" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/><g fill="#70f3cb"><circle cx="30" cy="125" r="3"/><circle cx="114" cy="99" r="3"/><circle cx="198" cy="113" r="3"/><circle cx="282" cy="69" r="3"/><circle cx="366" cy="88" r="3"/><circle cx="450" cy="28" r="3"/><circle cx="534" cy="54" r="3"/></g><g fill="#a6b5c4" font-size="10" font-family="monospace"><text x="23" y="163">D1</text><text x="107" y="163">D2</text><text x="191" y="163">D3</text><text x="275" y="163">D4</text><text x="359" y="163">D5</text><text x="443" y="163">D6</text><text x="527" y="163">D7</text></g></svg><p class="chart-caption"><?php esc_html_e( 'Illustrative signal volume. No external data sources connected.', 'cyberdat' ); ?></p></div>
 <div class="severity-panel"><div class="panel-heading"><h3><?php esc_html_e( 'Severity distribution', 'cyberdat' ); ?></h3><span>SAMPLE</span></div><div class="severity-chart"><div class="severity-ring" role="img" aria-label="Sample findings: 6 critical, 18 high, 40 medium, 64 low"><span><strong>128</strong><small>FINDINGS</small></span></div><ul class="severity-legend"><li><span class="legend-dot critical"></span>Critical <strong>06</strong></li><li><span class="legend-dot high"></span>High <strong>18</strong></li><li><span class="legend-dot medium"></span>Medium <strong>40</strong></li><li><span class="legend-dot low"></span>Low <strong>64</strong></li></ul></div></div></div>
 <div class="vulnerability-panel"><div class="panel-heading"><h3><?php esc_html_e( 'Vulnerability watch', 'cyberdat' ); ?></h3><span><?php esc_html_e( 'Fictional IDs · Not official CVEs', 'cyberdat' ); ?></span></div><div class="vulnerability-scroll" role="region" aria-label="Sample vulnerability table" tabindex="0"><table class="vulnerability-table"><thead><tr><th scope="col">DEMO CVE ID</th><th scope="col">COMPONENT</th><th scope="col">SEVERITY</th><th scope="col">DEMO SCORE</th><th scope="col">REVIEW STATUS</th></tr></thead><tbody>
 <?php foreach ( [['CVE-DEMO-0001', 'Example Edge Gateway', 'Critical', '9.8', 'Review required'], ['CVE-DEMO-0002', 'Example Identity Service', 'High', '8.1', 'Under analysis'], ['CVE-DEMO-0003', 'Example Workflow Engine', 'Medium', '6.4', 'Research queued']] as $row ) : ?>
 <tr><td><code><?php echo esc_html( $row[0] ); ?></code></td><td><?php echo esc_html( $row[1] ); ?></td><td><span class="severity-pill severity-<?php echo esc_attr( strtolower( $row[2] ) ); ?>"><?php echo esc_html( $row[2] ); ?></span></td><td><?php echo esc_html( $row[3] ); ?><small> / 10</small></td><td><span class="table-status"><?php echo esc_html( $row[4] ); ?></span></td></tr>
 <?php endforeach; ?></tbody></table></div></div>
 <div class="intel-footer"><span><?php esc_html_e( 'SAMPLE DATA · For visual evaluation only. No threat assessment.', 'cyberdat' ); ?></span><a href="<?php echo esc_url( home_url( '/topics/threat-intelligence/' ) ); ?>"><?php esc_html_e( 'Explore threat intelligence', 'cyberdat' ); ?> ↗</a></div></div>
</section>
<?php cyberdat_prototype_section( 'Latest Analysis', 'BEYOND THE HEADLINE', 'editorial_format', ['analysis'], '/analysis/', 'analysis' ); ?>
<?php cyberdat_prototype_section( 'AI Security', 'THE NEXT SECURITY FRONTIER', 'category', ['ai-security'], '/topics/ai-security/', 'ai' ); ?>
<?php cyberdat_prototype_section( 'Guides & Learning', 'TURN INSIGHT INTO PRACTICE', 'editorial_format', ['guides', 'learning'], '/guides/', 'learning' ); ?>
<div class="home-closing"><span class="terminal-mark" aria-hidden="true">&gt;_</span><p><?php esc_html_e( 'Clarity in a complex threat landscape.', 'cyberdat' ); ?></p><span>CYBERDAT / SAMPLE EDITION</span></div>
<?php get_footer(); ?>
