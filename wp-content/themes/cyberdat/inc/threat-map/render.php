<?php
/**
 * Global Cyber Threat Map: server HTML.
 * The server renders the interactive layout as it first appears (first layer, 7 days, its top 10, a map box of
 * fixed proportions), so the script changes no layout on load. Without JavaScript a <noscript> block shows every
 * layer with its status and a top-10 table, and hides the controls that need the script.
 */
defined('ABSPATH') || exit;

const CDTM_STATUS_LABELS = ['ok' => 'Updated', 'stale' => 'Stale', 'unavailable' => 'Unavailable', 'not_configured' => 'Not configured'];

function cyberdat_threat_map_top_items(array $top): string {
	$out = '';
	$max = $top ? max(1, $top[0]['n']) : 1;
	foreach ($top as $i => $row) {
		$pct = max(3, (int) round($row['n'] / $max * 100));
		$out .= '<li><button type="button" data-cdtm-cc="' . esc_attr($row['cc']) . '"><span class="cdtm-rank">' . ((int) $i + 1) . '</span>'
			. '<span class="cdtm-top-name"><span>' . esc_html($row['name']) . '</span><span class="cdtm-bar"><span style="width:' . $pct . '%"></span></span></span>'
			. '<span class="cdtm-top-n">' . esc_html(number_format_i18n($row['n'])) . '</span></button></li>';
	}
	return $out;
}

function cyberdat_threat_map_render(?array $snapshot, int $now): string {
	$model = CDTM_View::model($snapshot, $now);
	$first = $model['layers'][0];
	$period = CDTM_View::DEFAULT_PERIOD;
	$h = static fn($s) => esc_html($s);
	$a = static fn($s) => esc_attr($s);
	ob_start();
	?>
<section class="cdtm" id="global-threat-map" aria-labelledby="cdtm-title" data-threat-map="cdtm-1" data-geometry="<?php echo esc_url(get_theme_file_uri('/assets/maps/threat-map-countries.json')); ?>">
<noscript><style>.cdtm-tabs,.cdtm-controls,.cdtm-stage{display:none!important}.cdtm-panel[hidden]{display:block!important}</style></noscript>
<div class="cdtm-head"><div><p class="eyebrow">GEOGRAPHIC OBSERVATIONS / AGGREGATED BY COUNTRY</p><h2 id="cdtm-title">Global Cyber Threat Map</h2>
<p class="cdtm-intro">Where botnet command-and-control servers and reported ransomware victims are located, counted per country from public sources. The CyberDat server collects the data every hour; your browser never contacts the sources.</p></div>
<span class="cdtm-badge">COUNTRY TOTALS · CACHED ON CYBERDAT</span></div>
<p class="cdtm-disclaimer"><strong>Location of a server or victim does not establish attacker origin.</strong> Country totals only; no attack paths are drawn.</p>
<div class="cdtm-tabs" role="tablist" aria-label="Data layer" data-cdtm-tabs>
<?php foreach ($model['layers'] as $l): $on = $l['id'] === $first['id']; ?>
<button type="button" role="tab" id="cdtm-tab-<?php echo $a($l['id']); ?>" aria-controls="cdtm-panel-<?php echo $a($l['id']); ?>" aria-selected="<?php echo $on ? 'true' : 'false'; ?>" data-cdtm-tab="<?php echo $a($l['id']); ?>"><span class="cdtm-tab-name"><?php echo $h($l['name']); ?></span><span class="cdtm-tab-source"><?php echo $h($l['source']); ?></span><span class="cdtm-chip cdtm-chip--<?php echo $a($l['status']); ?>"><?php echo $h(CDTM_STATUS_LABELS[$l['status']]); ?></span></button>
<?php endforeach; ?>
</div>
<div class="cdtm-controls" data-cdtm-controls><div class="cdtm-periods" role="group" aria-label="Period">
<?php foreach (CDTM_View::PERIOD_LABELS as $p => $label): ?>
<button type="button" aria-pressed="<?php echo $p === $period ? 'true' : 'false'; ?>" data-cdtm-period="<?php echo $a($p); ?>"><?php echo $h($label); ?></button>
<?php endforeach; ?>
</div><p class="cdtm-unit" data-cdtm-unit><?php echo $h(ucfirst($first['unit'])); ?> · <?php echo $h(CDTM_View::PERIOD_LABELS[$period]); ?></p></div>
<?php foreach ($model['layers'] as $l): $pd = $l['periods'][$period]; $on = $l['id'] === $first['id']; ?>
<div class="cdtm-panel" role="tabpanel" id="cdtm-panel-<?php echo $a($l['id']); ?>" aria-labelledby="cdtm-tab-<?php echo $a($l['id']); ?>" data-cdtm-panel="<?php echo $a($l['id']); ?>" data-status="<?php echo $a($l['status']); ?>"<?php echo is_int($l['last_success']) ? ' data-updated="' . $a((string) $l['last_success']) . '"' : ''; ?><?php echo $on ? '' : ' hidden'; ?>>
<h3 class="cdtm-panel-title"><?php echo $h($l['name']); ?> <span>· <?php echo $h($l['source']); ?></span></h3>
<p class="cdtm-status cdtm-status--<?php echo $a($l['status']); ?>" data-cdtm-status><?php echo $h($l['status_text']); ?></p>
<?php if ($l['error_retrying']): ?><p class="cdtm-note">The latest collection attempt failed; the last good data is shown until the next successful run.</p><?php endif; ?>
<p class="cdtm-note"><?php echo $h($l['metric']); ?> <?php echo $h($l['note']); ?></p>
<p class="cdtm-note" data-cdtm-collecting><?php echo $h($pd['collecting']); ?></p>
<?php if ($l['show']): ?>
<noscript><div class="cdtm-table"><table><caption>Top 10 countries · <?php echo $h($pd['label']); ?> · <?php echo $h($l['unit']); ?></caption>
<thead><tr><th scope="col">#</th><th scope="col">Country</th><th scope="col"><?php echo $h(ucfirst($l['unit'])); ?></th></tr></thead><tbody>
<?php foreach ($pd['top'] as $i => $row): ?><tr><td><?php echo (int) $i + 1; ?></td><td><?php echo $h($row['name']); ?></td><td><?php echo $h(number_format_i18n($row['n'])); ?></td></tr>
<?php endforeach; if (!$pd['top']): ?><tr><td colspan="3">No country totals in this period.</td></tr><?php endif; ?>
</tbody></table><p class="cdtm-note">The interactive map, other periods and country details need JavaScript.</p></div></noscript>
<?php endif; ?>
<div class="cdtm-slot" data-cdtm-slot><?php if ($on): ?>
<div class="cdtm-stage" data-cdtm-stage data-state="<?php echo $l['show'] ? 'data' : 'nodata'; ?>">
<div class="cdtm-mapbox"><div class="cdtm-map" data-cdtm-map role="group" aria-label="World map shaded by country totals. For keyboard access use the top 10 list or the country search."></div>
<div class="cdtm-tip" data-cdtm-tip aria-hidden="true" hidden></div>
<div class="cdtm-legend" data-cdtm-legend></div>
<p class="cdtm-mapnote">Map: Natural Earth (public domain) via world-atlas 2.0.2 (ISC). Country shapes do not imply political boundaries.</p></div>
<div class="cdtm-side">
<div class="cdtm-country" data-cdtm-country aria-live="polite"><p class="cdtm-kicker">COUNTRY DETAILS</p><p>Select a country on the map, in the top 10 or in the search to see its total, the change against the previous period, a breakdown and a link to the source records.</p></div>
<div class="cdtm-top"><h4 data-cdtm-top-title>Top 10 countries · <?php echo $h($pd['label']); ?></h4><ol data-cdtm-top><?php echo cyberdat_threat_map_top_items($l['show'] ? $pd['top'] : []); ?></ol><p class="cdtm-note" data-cdtm-top-empty<?php echo $l['show'] && $pd['top'] ? ' hidden' : ''; ?>><?php echo $h($l['show'] ? 'No country totals in this period.' : 'No data to show for this layer.'); ?></p></div>
<div class="cdtm-search"><label for="cdtm-search-input">Find a country</label><input id="cdtm-search-input" type="search" autocomplete="off" data-cdtm-search><ul data-cdtm-results aria-label="Matching countries"></ul></div>
</div></div>
<?php endif; ?></div>
<p class="cdtm-source">Source: <a href="<?php echo esc_url($l['source_url']); ?>" rel="noopener noreferrer"><?php echo $h($l['source']); ?></a> · <a href="<?php echo esc_url($l['terms_url']); ?>" rel="noopener noreferrer">terms of use</a>. <?php echo $h($l['terms']); ?></p>
</div>
<?php endforeach; ?>
<script type="application/json" data-cdtm-data><?php echo wp_json_encode(CDTM_View::client_data($snapshot, $model), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES); ?></script>
</section>
<?php
	return (string) ob_get_clean();
}
