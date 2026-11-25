<?php
/**
 * Global Cyber Threat Map v1.1: Cloudflare Radar layer (percentages from the API, no own history), default tab and
 * tab order from the data, "Low activity" note, flags in the server HTML. Offline: memory store, fake HTTP, fixed clock.
 *   php tests/threat-map-layers.test.php
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

$passed = 0;
function check($ok, $message) { global $passed; if (!$ok) { fwrite(STDERR, "FAIL: $message\n"); exit(1); } $passed++; echo "PASS: $message\n"; }
function throws(callable $f, string $needle): bool { try { $f(); } catch (CDTM_Error $e) { return str_contains($e->getMessage(), $needle); } return false; }
function L(array $model, string $id): array { foreach ($model['layers'] as $l) { if ($l['id'] === $id) return $l; } throw new RuntimeException('no layer ' . $id); }

$RADAR = file_get_contents(__DIR__ . '/fixtures/threat-map/radar-l7-target-7d.json');
$T0 = gmmktime(19, 47, 30, 11, 24, 2026); // minute 47: the Radar slot

/* ---------- Cloudflare Radar: parsing ---------- */
$p = CDTM_Source_Radar::parse($RADAR);
$raw = json_decode($RADAR, true)['result'];
check(count($p['countries']) === 60 && $p['countries']['US']['v'] === round((float) $raw['top_0'][0]['value'], 4), 'Radar: 60 countries, the percentage kept as given (rounded to 4 decimals)');
check(is_float($p['countries']['US']['v']) && $p['countries']['US']['v'] < 100 && abs(array_sum(array_column($p['countries'], 'v')) - 100) < 0.01, 'Radar: values stay percentages (sum ≈ 100), never counts');
check($p['countries']['RS']['prev'] === 0.0 && is_float($p['countries']['DE']['prev']), 'Radar: comparison window from top_1; a country missing there compares with 0');
check($p['window'] === [gmmktime(19, 0, 0, 11, 17, 2026), gmmktime(19, 0, 0, 11, 24, 2026)] && $p['control'] === [gmmktime(19, 0, 0, 11, 10, 2026), gmmktime(19, 0, 0, 11, 17, 2026)] && $p['last_updated'] === '2026-11-24T19:15:00Z', 'Radar: both windows and lastUpdated from meta');
$mut = static function (callable $f) use ($RADAR) { $d = json_decode($RADAR, true); $f($d); return json_encode($d); };
check(throws(fn() => CDTM_Source_Radar::parse($mut(fn(&$d) => $d['result']['meta']['normalization'] = 'MIN0_MAX')), 'not percentages'), 'Radar: anything but PERCENTAGE normalisation is rejected (no unit mix-up)');
check(throws(fn() => CDTM_Source_Radar::parse('{"success":false,"errors":[{"code":9106,"message":"Missing X-Auth-Key, X-Auth-Email or Authorization headers"}],"result":null}'), 'not a successful'), 'Radar: an API error object is rejected');
check(throws(fn() => CDTM_Source_Radar::parse($mut(fn(&$d) => $d['result']['top_0'][0]['value'] = '250')), 'out of range') && throws(fn() => CDTM_Source_Radar::parse($mut(fn(&$d) => $d['result']['top_0'][3]['value'] = 'n/a')), 'numeric') && throws(fn() => CDTM_Source_Radar::parse('<html>'), 'format'), 'Radar: values out of 0..100, non-numeric values and HTML are rejected');
check(count(CDTM_Source_Radar::parse($mut(fn(&$d) => $d['result']['top_0'][] = ['targetCountryAlpha2' => 'https://x.example', 'value' => '0.1']))['countries']) === 61 && isset(CDTM_Source_Radar::parse($mut(fn(&$d) => $d['result']['top_0'][] = ['targetCountryAlpha2' => 'https://x.example', 'value' => '0.1']))['countries']['ZZ']), 'Radar: an invalid country code becomes unknown (ZZ), never stored as text');
$plan = CDTM_Source_Radar::plan([], $T0);
check(array_column($plan, 'id') === ['24h', '7d', '30d'] && str_contains($plan[0]['url'], 'dateRange=1d&dateRange=1dcontrol&mitigationProduct=DDOS&limit=200&format=json') && str_starts_with($plan[2]['url'], 'https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/target?dateRange=30d&dateRange=30dcontrol'), 'Radar: three requests (1d / 7d / 30d, each with its control window), L7 DDoS, HTTPS on api.cloudflare.com');

/* ---------- Cloudflare Radar: sync ---------- */
final class FakeHttp {
	public array $calls = [];
	public array $queue = [];
	public function __invoke(string $url, array $headers, int $max, int $timeout): array {
		$this->calls[] = ['url' => $url, 'headers' => $headers];
		$r = array_shift($this->queue) ?? ['error' => 'no response queued'];
		return is_callable($r) ? $r($url) : $r;
	}
}
$store = new CDTM_Memory_Store();
$http = new FakeHttp();
check(CDTM::sync_layer($store, $http, 'radar', $T0)['result'] === 'not_configured' && !$http->calls && L(CDTM_View::model(CDTM::snapshot($store), $T0), 'radar')['status'] === 'not_configured', 'Radar: without CYBERDAT_CLOUDFLARE_RADAR_TOKEN the layer is "not configured" and makes no request');
$token = 'cf-test-' . bin2hex(random_bytes(10));
define('CYBERDAT_CLOUDFLARE_RADAR_TOKEN', $token);
$http->queue = [['code' => 200, 'headers' => [], 'body' => $RADAR], ['code' => 200, 'headers' => [], 'body' => $RADAR], ['code' => 200, 'headers' => [], 'body' => $RADAR]];
$res = CDTM::sync_layer($store, $http, 'radar', $T0);
check($res['result'] === 'ok' && count($http->calls) === 3 && $http->calls[0]['headers']['Authorization'] === 'Bearer ' . $token && !isset($http->calls[0]['headers']['X-API-KEY']), 'Radar: token sent only as "Authorization: Bearer"');
check(!str_contains(json_encode([$store->meta, $store->counts]), $token), 'Radar: token not stored');
check($store->count_rows('radar', 'h') === 0 && $store->count_rows('radar', 'd') === 0, 'Radar: no own history (the API gives the periods and the comparison)');
$snap = CDTM::snapshot($store);
$p7 = $snap['layers']['radar']['periods']['7d'];
check($p7['comparable'] === true && $p7['complete'] === true && $p7['control'] === [gmmktime(19, 0, 0, 11, 10, 2026), gmmktime(19, 0, 0, 11, 17, 2026)] && $p7['countries']['US']['n'] === $p['countries']['US']['v'] && $p7['countries']['US']['prev'] === $p['countries']['US']['prev'], 'Radar snapshot: shares and comparison window exactly as the API gave them');
check(array_keys($p7['countries'])[0] === 'US' && $p7['countries']['US']['b'] === [], 'Radar snapshot: sorted by share, no breakdown');
check(CDTM::sync_layer($store, $http, 'radar', $T0 + 600, true)['result'] === 'skipped' && count($http->calls) === 3, 'Radar: MIN_INTERVAL 1800 s also for --force');
check(CDTM::due(CDTM::layers()['radar'], ['last_attempt' => $T0], $T0 + 3600) && !CDTM::due(CDTM::layers()['radar'], ['last_attempt' => $T0], $T0 + 3600 - 40 * 60) && !CDTM::due(CDTM::layers()['feodo'], ['last_attempt' => $T0 - 3600], $T0), 'Radar: own slot :47 (Feodo :07 and Ransomware :27 not at :47)');
$http->queue = [['code' => 200, 'headers' => [], 'body' => $RADAR], ['code' => 503, 'headers' => [], 'body' => 'busy']];
$before = CDTM::state($store, 'radar')['radar'];
$res = CDTM::sync_layer($store, $http, 'radar', $T0 + 3600);
check($res['result'] === 'error' && $res['message'] === 'HTTP 503 from api.cloudflare.com' && CDTM::state($store, 'radar')['radar'] === $before && CDTM::state($store, 'radar')['last_success'] === $T0, 'Radar error: all-or-nothing, last good periods kept');
$rows = CDTM::status_rows($store, $T0 + 3600);
check(str_starts_with($rows[array_search('radar', array_column($rows, 'layer'))]['history'], 'no own history (periods from the API): 3 of 3'), 'status: Radar history line');
$m = CDTM_View::model(CDTM::snapshot($store), $T0 + 3700);
$top = L($m, 'radar')['periods']['7d']['top'];
check($top[0]['cc'] === 'US' && $top[0]['text'] === number_format($p['countries']['US']['v'], 2) . '%' && count($top) === 10, 'Radar page: top 10 written as percentages with two decimals');

/* ---------- default tab and tab order ---------- */
$mk = static fn(string $id, string $status, int $countries) => ['id' => $id, 'status' => $status, 'countries' => $countries];
$ids = static fn(array $l) => implode(',', array_column(CDTM_View::order($l), 'id'));
$cases = [
	// [ransomware, radar, feodo] → expected order
	[[['ok', 80], ['ok', 60], ['ok', 3]], 'ransomware,radar,feodo', 'all ok: most countries first'],
	[[['ok', 40], ['ok', 60], ['ok', 3]], 'radar,ransomware,feodo', 'Radar has more countries'],
	[[['ok', 60], ['ok', 60], ['ok', 60]], 'ransomware,radar,feodo', 'tie: Ransomware.live first'],
	[[['ok', 0], ['ok', 0], ['ok', 4]], 'feodo,ransomware,radar', 'only Feodo has data'],
	[[['not_configured', 0], ['ok', 60], ['ok', 3]], 'radar,feodo,ransomware', 'Ransomware.live without key'],
	[[['stale', 90], ['ok', 2], ['unavailable', 0]], 'radar,ransomware,feodo', 'stale is not ok even with more countries'],
	[[['stale', 90], ['stale', 60], ['unavailable', 0]], 'ransomware,radar,feodo', 'none ok: Ransomware.live first'],
	[[['not_configured', 0], ['not_configured', 0], ['unavailable', 0]], 'ransomware,radar,feodo', 'nothing collected: Ransomware.live first with its own status'],
	[[['not_configured', 0], ['stale', 5], ['stale', 3]], 'ransomware,radar,feodo', 'none ok, Ransomware.live not configured: still first'],
	[[['ok', 3], ['not_configured', 0], ['ok', 3]], 'ransomware,feodo,radar', 'tie between ok layers with few countries'],
];
foreach ($cases as [$st, $want, $label]) {
	$layers = [$mk('ransomware', ...$st[0]), $mk('radar', ...$st[1]), $mk('feodo', ...$st[2])];
	check($ids($layers) === $want && $ids(array_reverse($layers)) === $want, "default tab: $label → $want");
}

/* ---------- low activity ---------- */
$feodoOnly = new CDTM_Memory_Store();
$h = new FakeHttp();
$h->queue = [['code' => 200, 'headers' => [], 'body' => json_encode([['ip_address' => '192.0.2.1', 'country' => 'US', 'malware' => 'QakBot'], ['ip_address' => '192.0.2.2', 'country' => 'JP', 'malware' => 'QakBot']])]];
CDTM::sync_layer($feodoOnly, $h, 'feodo', $T0);
$mf = CDTM_View::model(CDTM::snapshot($feodoOnly), $T0 + 60);
check(L($mf, 'feodo')['periods']['7d']['low'] === true && L($mf, 'feodo')['periods']['7d']['countries'] === 2 && L($m, 'radar')['periods']['7d']['low'] === false, 'low activity: flagged below 5 countries, not for 60');
check($mf['default'] === 'feodo', 'default tab: the only ok layer opens even with low activity');
$hf = cyberdat_threat_map_render(CDTM::snapshot($feodoOnly), $T0 + 60);
check(preg_match('~<p class="cdtm-note cdtm-low" data-cdtm-low>Low activity in the source right now~', $hf) === 1 && preg_match('~<span class="cdtm-top-n">1</span>.*<span class="cdtm-top-n">1</span>~s', $hf) === 1, 'low activity: note under the map, numbers unchanged (1 and 1)');
$hr = cyberdat_threat_map_render(CDTM::snapshot($store), $T0 + 3700);
check(preg_match('~data-cdtm-low hidden>~', $hr) === 1, 'low activity: hidden for a layer with 60 countries');

/* ---------- server HTML: order, flags, attribution ---------- */
check(preg_match_all('~data-cdtm-tab="([a-z]+)"~', $hr, $mm) && implode(',', $mm[1]) === 'radar,ransomware,feodo' && str_contains($hr, 'aria-selected="true" data-cdtm-tab="radar"'), 'HTML: the only ok layer (Radar) is the first and selected tab');
check(substr_count($hr, 'class="cdtm-flag" src="/wp-content/themes/cyberdat/assets/flags/4x3/') === 10 && str_contains($hr, '<img class="cdtm-flag" src="/wp-content/themes/cyberdat/assets/flags/4x3/us.svg" width="20" height="15" loading="lazy" decoding="async" alt="">United States'), 'HTML: top 10 with flags (fixed size, lazy, empty alt, name next to it)');
check(cyberdat_threat_map_flag('QQ') === '<span class="cdtm-flag cdtm-flag--none" aria-hidden="true"></span>' && cyberdat_threat_map_flag('<x>') === cyberdat_threat_map_flag('QQ'), 'flags: neutral placeholder of the same size without a file or a valid code');
check(str_contains($hr, 'Source: <a href="https://radar.cloudflare.com/"') && str_contains($hr, 'https://creativecommons.org/licenses/by-nc/4.0/') && str_contains($hr, 'Data: Cloudflare Radar (radar.cloudflare.com), licensed under CC BY-NC 4.0.') && str_contains($hr, 'Location of a server or victim does not establish attacker origin.'), 'HTML: Radar attribution with the license link; attacker-origin notice kept');
check(str_contains($hr, '% of observed attacks') && !preg_match('~reported victims · 7 days~', $hr) && preg_match('~data-flags="/wp-content/themes/cyberdat/assets/flags/4x3/"~', $hr) === 1, 'HTML: unit "% of observed attacks"; flags base on the theme');
preg_match('~<script type="application/json" data-cdtm-data>(.*?)</script>~s', $hr, $js);
$cd = json_decode($js[1], true);
check(count(explode(',', $cd['flags'])) === 250 && $cd['low'] === 5 && $cd['layers']['radar']['kind'] === 'share', 'client data: flag list (250), low-activity threshold, layer kind');

echo "PASS: threat map layers — $passed checks, no network, database or WordPress\n";
