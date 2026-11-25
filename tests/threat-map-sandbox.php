<?php
/**
 * Local browser stand for the Global Cyber Threat Map: renders full pages with the theme CSS/JS and a snapshot
 * built by the real collector core from SYNTHETIC data (no network, no WordPress, no database).
 *   php tests/threat-map-sandbox.php <out-dir>     → <out-dir>/{data,stale,unavailable,empty,notconfigured}.html
 * Served by tests/threat-map-sandbox-server.cjs. Every page carries a "LOCAL TEST STAND · synthetic data" banner.
 */
define('ABSPATH', __DIR__ . '/');
function esc_html($s) { return htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function esc_attr($s) { return esc_html($s); }
function esc_url($s) { return esc_html($s); }
function number_format_i18n($n) { return number_format($n); }
function get_theme_file_uri($p) { return '/wp-content/themes/cyberdat' . $p; }
function wp_json_encode($v, $f = 0) { return json_encode($v, $f); }
$theme = __DIR__ . '/../wp-content/themes/cyberdat';
require $theme . '/inc/threat-map/core.php';
require $theme . '/inc/threat-map/view.php';
require $theme . '/inc/threat-map/render.php';
$out = $argv[1] ?? '';
if ($out === '' || !is_dir($out)) { fwrite(STDERR, "usage: php tests/threat-map-sandbox.php <existing-out-dir>\n"); exit(2); }
$withKey = !in_array('--no-key', $argv, true);
if ($withKey) define('CYBERDAT_RANSOMWARE_LIVE_API_KEY', 'sandbox-' . bin2hex(random_bytes(6)));

$T = gmmktime(19, 27, 30, 11, 24, 2026);
mt_srand(20261124);
$weights = ['US' => 40, 'DE' => 12, 'GB' => 10, 'FR' => 9, 'CA' => 8, 'IT' => 7, 'BR' => 6, 'ES' => 6, 'AU' => 5, 'IN' => 5, 'NL' => 4, 'MX' => 4, 'JP' => 3, 'CH' => 3,
	'BE' => 3, 'TR' => 3, 'PL' => 2, 'SE' => 2, 'AR' => 2, 'ZA' => 2, 'TH' => 2, 'ID' => 2, 'CO' => 2, 'AT' => 1, 'CL' => 1, 'PT' => 1, 'IL' => 1, 'SG' => 1, 'KR' => 1, 'EG' => 1, 'NG' => 1, 'NZ' => 1, 'PE' => 1, 'CZ' => 1, 'NO' => 1, 'GR' => 1];
$sectors = ['Manufacturing', 'Healthcare', 'Business Services', 'Technology', 'Education', 'Construction', 'Financial Services', 'Retail', 'Government', 'Transportation/Logistics', 'Not Found'];
$pick = static function (array $w) { $r = mt_rand(1, array_sum($w)); foreach ($w as $k => $v) { if (($r -= $v) <= 0) return $k; } return array_key_last($w); };
$month = static function (int $m) use ($T, $weights, $sectors, $pick) {
	$rows = [];
	for ($t = $m; $t < CDTM::next_month($m) && $t <= $T; $t += 3600) {
		if (mt_rand(0, 99) < 70) for ($i = mt_rand(0, 2); $i > 0; $i--) $rows[] = ['victim' => 'VICTIM-PLACEHOLDER', 'discovered' => gmdate('Y-m-d H:i:s', $t + mt_rand(0, 3599)), 'country' => $pick($weights), 'activity' => $sectors[mt_rand(0, count($sectors) - 1)], 'website' => ''];
	}
	return json_encode($rows);
};
$feodo = static function (int $k) {
	$c = ['US', 'US', 'US', 'DE', 'NL', 'FR', 'RU', 'GB', 'JP', 'BR', 'SG', 'US', 'DE'];
	$f = ['QakBot', 'Emotet', 'Pikabot', 'Dridex', 'TrickBot'];
	$rows = [];
	for ($i = 0; $i < 9 + $k % 4; $i++) $rows[] = ['ip_address' => '192.0.2.' . ($i + 1), 'country' => $c[$i % count($c)], 'malware' => $f[($i + $k) % count($f)]];
	return json_encode($rows);
};

$store = new CDTM_Memory_Store();
$http = static function ($url) use ($month, $feodo, &$tick) {
	if (str_contains($url, 'feodotracker')) return ['code' => 200, 'headers' => [], 'body' => $feodo($tick)];
	parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
	return ['code' => 200, 'headers' => [], 'body' => $month(gmmktime(0, 0, 0, (int) $q['month'], 1, (int) $q['year']))];
};
// Feodo: 9 days of hourly runs (history since then); Ransomware.live: one run backfills its 60 days.
for ($tick = 0, $t = CDTM::floor_hour($T) - 9 * 86400 + 7 * 60; $t <= $T; $t += 3600, $tick++) CDTM::sync_layer($store, $http, 'feodo', $t, true);
CDTM::sync_layer($store, $http, 'ransomware', $T, true);
$snapshot = CDTM::snapshot($store);

$css = ['tokens', 'main', 'threat-dashboard', 'threat-geo', 'threat-map'];
$page = static function (?array $snap, int $now, string $label) use ($css) {
	$links = implode('', array_map(static fn($c) => '<link rel="stylesheet" href="/wp-content/themes/cyberdat/assets/css/' . $c . '.css">', $css));
	return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Threat map stand · ' . esc_html($label) . '</title>' . $links . '</head>'
		. '<body class="page-template-threat-intelligence"><main id="main-content" class="site-main container" tabindex="-1">'
		. '<p data-stand-banner style="margin:1rem 0;padding:.5rem .8rem;border:1px solid #8a6420;border-radius:.4rem;background:#3a2a0c;color:#ffd9a0;font:600 .8rem monospace">LOCAL TEST STAND · synthetic data (' . esc_html($label) . ') · not real observations</p>'
		. '<header class="ti-page-header"><p class="eyebrow">RESEARCH / EVIDENCE / CONTEXT</p><h1>Threat Intelligence</h1></header>'
		. cyberdat_threat_map_render($snap, $now)
		. '<section style="min-height:40rem"><h2>Intelligence Overview</h2><p>Placeholder for the section below the map (layout-shift check).</p></section>'
		. '</main><script src="/wp-content/themes/cyberdat/assets/js/threat-map.js" defer></script></body></html>';
};
$pages = $withKey
	? ['data' => [$snapshot, $T + 10 * 60], 'stale' => [$snapshot, $T + 4 * 3600], 'unavailable' => [$snapshot, $T + 49 * 3600], 'empty' => [null, $T]]
	: ['notconfigured' => [$snapshot, $T + 10 * 60]];
foreach ($pages as $name => [$snap, $now]) file_put_contents($out . '/' . $name . '.html', $page($snap, $now, $name));
echo 'wrote ' . implode(', ', array_keys($pages)) . "\n";
