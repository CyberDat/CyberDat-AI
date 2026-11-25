<?php
/**
 * Global Cyber Threat Map collector, history, statuses and server HTML. Offline: an in-memory store, a fake HTTP
 * client and a fixed clock; no WordPress, network or database.
 *   php tests/threat-map.test.php
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
/** A layer of the page model by id (the tab order depends on the data). */
function L(array $model, string $id): array { foreach ($model['layers'] as $l) { if ($l['id'] === $id) return $l; } throw new RuntimeException('no layer ' . $id); }
function throws(callable $f, string $needle): bool { try { $f(); } catch (CDTM_Error $e) { return str_contains($e->getMessage(), $needle); } return false; }

$FEODO = file_get_contents(__DIR__ . '/fixtures/threat-map/feodo-ipblocklist.json');
$RANSOM = file_get_contents(__DIR__ . '/fixtures/threat-map/ransomware-2026-11.json');
$T0 = gmmktime(19, 7, 30, 11, 24, 2026); // minute 07: the Feodo slot

/** Fake HTTP client: a queue of responses per host; records every request. */
final class FakeHttp {
	public array $calls = [];
	public array $queue = [];
	public function __invoke(string $url, array $headers, int $max, int $timeout): array {
		$this->calls[] = ['url' => $url, 'headers' => $headers, 'max' => $max, 'timeout' => $timeout];
		$host = parse_url($url, PHP_URL_HOST);
		$r = array_shift($this->queue[$host]) ?? ['error' => 'no response queued'];
		return is_callable($r) ? $r($url, $headers) : $r;
	}
	public function add(string $host, array|Closure $response): void { $this->queue[$host][] = $response; }
}
$ok = static fn(string $body, array $h = []) => ['code' => 200, 'headers' => $h, 'body' => $body];

/* ---------- parsing and counting ---------- */
$p = CDTM_Source_Feodo::parse($FEODO);
check($p['items'] === 10 && $p['countries']['US']['n'] === 3 && $p['countries']['DE']['n'] === 2 && $p['countries']['ZZ']['n'] === 1, 'Feodo: count per ISO country, missing country counted as unknown');
check(array_sum($p['countries']['US']['b']) === 3 && isset($p['countries']['US']['b']['QakBot']), 'Feodo: count per malware family');
check(throws(fn() => CDTM_Source_Feodo::parse('{"a":1}'), 'format') && throws(fn() => CDTM_Source_Feodo::parse('[{"country":"US"}]'), 'format')
	&& throws(fn() => CDTM_Source_Feodo::parse('[{"ip_address":"not-an-ip","country":"US","malware":"X"}]'), 'ip_address') && throws(fn() => CDTM_Source_Feodo::parse('<html>'), 'format'), 'Feodo: wrong format is rejected');
check(CDTM_Source_Feodo::parse('[]')['countries'] === [], 'Feodo: an empty list (the dataset is nearly empty today) is valid');
$r = CDTM_Source_Ransomware::parse($RANSOM);
$us = count(array_filter($r['events'], fn($e) => $e[1] === 'US'));
check($r['items'] === 48 && $us === 16 && count(array_filter($r['events'], fn($e) => $e[1] === 'ZZ')) === 8, 'Ransomware: count per country; lower-case code normalised, empty/null country unknown');
check(in_array('Not specified', array_column($r['events'], 2), true) && in_array('Healthcare', array_column($r['events'], 2), true), 'Ransomware: sector kept, empty sector = Not specified');
check(count(CDTM_Source_Ransomware::parse('{"victims":' . $RANSOM . '}')['events']) === 48 && count(CDTM_Source_Ransomware::parse('{"data":' . $RANSOM . '}')['events']) === 48, 'Ransomware: list or wrapped list accepted');
check(throws(fn() => CDTM_Source_Ransomware::parse('{"error":"x"}'), 'format') && throws(fn() => CDTM_Source_Ransomware::parse('[{"discovered":"yesterday"},{"discovered":"no"}]'), 'discovered'), 'Ransomware: wrong format is rejected');
check(CDTM::parse_time('2026-11-24 10:12:33.123456') === [gmmktime(10, 12, 33, 11, 24, 2026), true] && CDTM::parse_time('2026-11-24T10:12:33Z')[1] && CDTM::parse_time('2026-11-24') === [gmmktime(0, 0, 0, 11, 24, 2026), false] && CDTM::parse_time('2026-02-30') === null, 'dates: UTC formats, date-only, invalid dates');
check(CDTM::label('https://evil.example/x', 'N') === 'Other' && CDTM::label('203.0.113.9', 'N') === 'Other' && CDTM::label('mail@example.org', 'N') === 'Other' && CDTM::label('example.com', 'N') === 'Other' && CDTM::label('Business Services', 'N') === 'Business Services', 'labels: URLs, IPs, e-mails and domains never become a label');
check(CDTM::label('Transportation/Logistics', 'N') === 'Transportation/Logistics' && CDTM::label('Not Found', 'N') === 'N' && CDTM::label('unknown', 'N') === 'N', 'labels: "a/b" sectors kept, source placeholders become "Not specified"');
$many = new CDTM_Memory_Store();
$many->replace_range('x', 'd', 0, 86400, array_merge([[0, 'US', '', 20], [0, 'US', 'Other', 5]], array_map(fn($i) => [0, 'US', 'S' . $i, 1], range(1, 10))));
$row = CDTM::period($many, ['id' => 'x', 'kind' => 'event'], ['history_since' => 0], '7d', 3 * 86400)['countries']['US'];
check(count(array_keys(array_column($row['b'], 0), 'Other')) === 1 && array_sum(array_column($row['b'], 1)) === 15 && count($row['b']) === 8, 'breakdown: at most 8 rows, the rest merged into a single "Other" row');

/* ---------- sync, history, periods ---------- */
$store = new CDTM_Memory_Store();
$http = new FakeHttp();
$http->add('feodotracker.abuse.ch', $ok($FEODO, ['etag' => '"v1"', 'last-modified' => 'Tue, 24 Nov 2026 18:00:00 GMT']));
$res = CDTM::sync_layer($store, $http, 'feodo', $T0);
check($res['result'] === 'ok' && $http->calls[0]['url'] === CDTM_Source_Feodo::URL && $http->calls[0]['timeout'] === 20 && $http->calls[0]['max'] === CDTM_Source_Feodo::MAX_BYTES, 'sync: HTTPS source fetched with 20 s timeout and size limit');
$st = CDTM::state($store, 'feodo');
check($st['last_success'] === $T0 && $st['status'] === 'ok' && $st['history_since'] === $T0 && $st['runs'] === 1, 'sync: state records success time, status, history start');
check($store->count_rows('feodo', 'h') > 0 && $store->count_rows('feodo', 'd') > 0, 'history: hourly and daily rows written');
$snap = CDTM::snapshot($store);
check($snap['layers']['feodo']['periods']['24h']['countries']['US']['n'] === 3 && $snap['names']['US'] === 'United States', 'snapshot: rebuilt after the sync with country names');
check($snap['layers']['feodo']['periods']['7d']['comparable'] === false && !isset($snap['layers']['feodo']['periods']['7d']['countries']['US']['prev']), 'history: no comparison with an empty previous period');
$model = CDTM_View::model($snap, $T0 + 60);
check(str_contains(L($model, 'feodo')['periods']['30d']['collecting'], 'Collecting data since 2026-11-24'), 'history: "Collecting data since <date>" while history is short');

// 304: no download, the hourly snapshot is recorded from the last good list
$http->add('feodotracker.abuse.ch', ['code' => 304, 'headers' => [], 'body' => '']);
$res = CDTM::sync_layer($store, $http, 'feodo', $T0 + 3600);
$last = end($http->calls);
check($res['result'] === 'not_modified' && $last['headers']['If-None-Match'] === '"v1"' && $last['headers']['If-Modified-Since'] === 'Tue, 24 Nov 2026 18:00:00 GMT', '304: conditional headers sent, success without download');
check(count($store->rows('feodo', 'h', CDTM::floor_hour($T0 + 3600), CDTM::floor_hour($T0 + 3600) + 3600)) > 0 && CDTM::state($store, 'feodo')['last_success'] === $T0 + 3600, '304: the hour is recorded from the last good list');

// gauge: daily value = the largest hourly value; 7 days uses daily peaks; 24 h compares with the previous 24 h
$gauge = new CDTM_Memory_Store();
$h = new FakeHttp();
$one = json_encode([['ip_address' => '192.0.2.1', 'country' => 'US', 'malware' => 'QakBot']]);
$two = json_encode([['ip_address' => '192.0.2.1', 'country' => 'US', 'malware' => 'QakBot'], ['ip_address' => '192.0.2.2', 'country' => 'US', 'malware' => 'QakBot']]);
$t = $T0 - 3 * 86400;
foreach ([$two, $one, $one] as $i => $body) { $h->add('feodotracker.abuse.ch', $ok($body)); CDTM::sync_layer($gauge, $h, 'feodo', $t + $i * 3600); }
$day = $gauge->rows('feodo', 'd', CDTM::floor_day($t), CDTM::floor_day($t) + 86400);
check(in_array([CDTM::floor_day($t), 'US', '', 2], $day, true), 'gauge: the day keeps the peak (2) although the last list had 1');
for ($i = 1; $i <= 2 * 24 + 2; $i++) { $h->add('feodotracker.abuse.ch', $ok($i % 2 ? $one : $two)); CDTM::sync_layer($gauge, $h, 'feodo', $t + 2 * 3600 + $i * 3600, true); }
$s = CDTM::rebuild_snapshot($gauge, $t + 2 * 3600 + 50 * 3600);
check($s['layers']['feodo']['periods']['24h']['comparable'] === true && $s['layers']['feodo']['periods']['24h']['countries']['US']['prev'] === 2 && $s['layers']['feodo']['periods']['24h']['countries']['US']['n'] === 2, '24 h: peak and previous 24 h peak from the hourly history');
$buckets = array_unique(array_column($gauge->rows('feodo', 'h', 0, PHP_INT_MAX), 0));
check(count($buckets) === CDTM::HOURLY_HOURS && min($buckets) === CDTM::floor_hour($t + 52 * 3600) - 47 * 3600, 'history: exactly the last 48 hourly buckets kept');

// daily retention: older than 60 days is deleted automatically
$old = new CDTM_Memory_Store();
$old->upsert_max('feodo', 'd', [[CDTM::floor_day($T0) - 61 * 86400, 'US', '', 5], [CDTM::floor_day($T0) - 59 * 86400, 'US', '', 4]]);
$old->replace_range('feodo', 'h', 0, PHP_INT_MAX, [[CDTM::floor_hour($T0) - 49 * 3600, 'US', '', 1], [CDTM::floor_hour($T0) - 47 * 3600, 'US', '', 1]]);
$h = new FakeHttp(); $h->add('feodotracker.abuse.ch', $ok($FEODO));
CDTM::sync_layer($old, $h, 'feodo', $T0);
check(!$old->rows('feodo', 'd', 0, CDTM::floor_day($T0) - 60 * 86400) && $old->rows('feodo', 'd', CDTM::floor_day($T0) - 59 * 86400, CDTM::floor_day($T0) - 58 * 86400), 'history: daily rows older than 60 days removed, 59 days kept');
check(!$old->rows('feodo', 'h', 0, CDTM::floor_hour($T0) - 48 * 3600) && $old->rows('feodo', 'h', CDTM::floor_hour($T0) - 47 * 3600, CDTM::floor_hour($T0) - 46 * 3600), 'history: hourly rows older than 48 h removed');

/* ---------- errors keep the last good data ---------- */
$before = json_encode([$store->counts, CDTM::snapshot($store)['layers']['feodo']['periods']]);
$cases = [
	'network' => ['error' => 'cURL error 6: Could not resolve host: feodotracker.abuse.ch'],
	'timeout' => ['error' => 'cURL error 28: Operation timed out after 20001 milliseconds with 0 bytes received for https://feodotracker.abuse.ch/downloads/ipblocklist.json?session=abc123'],
	'format' => $ok('<html>maintenance</html>'),
	'size' => ['code' => 200, 'headers' => ['content-length' => (string) (CDTM_Source_Feodo::MAX_BYTES + 1)], 'body' => '[]'],
	'size-body' => $ok(str_repeat(' ', CDTM_Source_Feodo::MAX_BYTES + 1) . '[]'),
	'http' => ['code' => 503, 'headers' => [], 'body' => 'busy'],
];
$i = 2;
foreach ($cases as $label => $response) {
	$http->add('feodotracker.abuse.ch', $response);
	$res = CDTM::sync_layer($store, $http, 'feodo', $T0 + $i++ * 3600, true);
	$st = CDTM::state($store, 'feodo');
	$snapNow = CDTM::snapshot($store);
	check($res['result'] === 'error' && $st['status'] === 'error' && $st['last_success'] === $T0 + 3600 && json_encode($store->counts) === json_encode(json_decode($before, true)[0])
		&& $snapNow['layers']['feodo']['last_success'] === $T0 + 3600 && $snapNow['layers']['feodo']['last_error_at'] === $T0 + ($i - 1) * 3600, "error ($label): history untouched, last good snapshot kept, error time recorded");
}
check(CDTM::state($store, 'feodo')['last_error']['message'] === 'HTTP 503 from feodotracker.abuse.ch', 'error text: status and host only');
$http->add('feodotracker.abuse.ch', $cases['timeout']);
CDTM::sync_layer($store, $http, 'feodo', $T0 + 20 * 3600, true);
$msg = CDTM::state($store, 'feodo')['last_error']['message'];
check(str_contains($msg, 'timed out') && !str_contains($msg, 'session=') && !str_contains($msg, 'https://') && !str_contains($msg, '/downloads/'), 'error text: timeout kept, URL reduced to the host (no path or parameters)');
check(throws(fn() => (function () { $c = new ReflectionMethod(CDTM::class, 'get'); $c->setAccessible(true); $c->invoke(null, fn() => [], CDTM::layers()['feodo'], ['id' => 'x', 'url' => 'http://feodotracker.abuse.ch/x', 'headers' => []], [], null); })(), 'HTTPS')
	&& throws(fn() => (function () { $c = new ReflectionMethod(CDTM::class, 'get'); $c->setAccessible(true); $c->invoke(null, fn() => [], CDTM::layers()['feodo'], ['id' => 'x', 'url' => 'https://evil.example/x', 'headers' => []], [], null); })(), 'HTTPS'), 'HTTP: only HTTPS on the source host');

/* ---------- schedule: slot, MIN_INTERVAL, lock ---------- */
$sched = new CDTM_Memory_Store();
$h = new FakeHttp();
$h->add('feodotracker.abuse.ch', $ok($FEODO));
CDTM::sync_layer($sched, $h, 'feodo', $T0);
$calls = count($h->calls);
check(CDTM::sync_layer($sched, $h, 'feodo', $T0 + 120, true)['result'] === 'skipped' && count($h->calls) === $calls, 'MIN_INTERVAL: --force within 300 s makes no request');
check(str_contains(CDTM::sync_layer($sched, $h, 'feodo', $T0 + 1200)['message'], 'not due') && count($h->calls) === $calls, 'schedule: no run 20 min later (outside the hourly slot)');
$at = gmmktime(20, 27, 0, 11, 24, 2026);
check(!CDTM::due(CDTM::layers()['feodo'], CDTM::state($sched, 'feodo'), $at) && CDTM::due(CDTM::layers()['feodo'], CDTM::state($sched, 'feodo'), gmmktime(20, 7, 5, 11, 24, 2026)), 'schedule: Feodo runs at :07, not at :27');
check(CDTM::due(CDTM::layers()['ransomware'], ['last_attempt' => $at - 3600], $at) && !CDTM::due(CDTM::layers()['ransomware'], ['last_attempt' => $at - 3600], $at + 20 * 60), 'schedule: Ransomware runs at :27, not at :47');
check(CDTM::due(CDTM::layers()['feodo'], ['last_attempt' => $at - 7300], $at), 'schedule: a missed slot is caught up after 2 h');
check($sched->lock('sync:feodo', CDTM::LOCK_TTL, $T0 + 7200), 'lock: taken by a running sync');
check(CDTM::sync_layer($sched, $h, 'feodo', $T0 + 7300, true)['message'] === 'another sync holds the lock' && count($h->calls) === $calls, 'lock: a second run makes no request');
check(!$sched->lock('sync:feodo', CDTM::LOCK_TTL, $T0 + 7200 + 899) && $sched->lock('sync:feodo', CDTM::LOCK_TTL, $T0 + 7200 + 900), 'lock: times out after 15 min (crashed run)');
$sched->unlock('sync:feodo');
$h->add('feodotracker.abuse.ch', $ok($FEODO));
check(CDTM::sync_layer($sched, $h, 'feodo', $T0 + 9000, true)['result'] === 'ok' && !isset($sched->locks['sync:feodo']), 'lock: released after the run');
check(CDTM_Source_Ransomware::MIN_INTERVAL === 1800 && CDTM_Source_Feodo::MIN_INTERVAL === 300, 'MIN_INTERVAL: 1800 s Ransomware.live (30-min cache), 300 s Feodo (5-min generation)');

/* ---------- statuses ---------- */
$s = ['last_success' => $T0];
check(CDTM::freshness($s, $T0 + 10800) === 'ok' && CDTM::freshness($s, $T0 + 10801) === 'stale' && CDTM::freshness($s, $T0 + 172800) === 'stale' && CDTM::freshness($s, $T0 + 172801) === 'unavailable' && CDTM::freshness([], $T0) === 'unavailable' && CDTM::freshness($s, $T0, false) === 'not_configured', 'status: ok ≤ 3 h < stale ≤ 48 h < unavailable');
$st = new CDTM_Memory_Store(); $h = new FakeHttp(); $h->add('feodotracker.abuse.ch', $ok($FEODO)); $h->add('feodotracker.abuse.ch', $ok($FEODO));
CDTM::sync_layer($st, $h, 'feodo', $T0);
$m1 = CDTM_View::model(CDTM::snapshot($st), $T0 + 4 * 3600);
$m2 = CDTM_View::model(CDTM::snapshot($st), $T0 + 49 * 3600);
check(L($m1, 'feodo')['status'] === 'stale' && L($m1, 'feodo')['show'] && str_starts_with(L($m1, 'feodo')['status_text'], 'Stale: last successful update 4 h'), 'status: stale after 3 h, numbers still shown with the time');
check(L($m2, 'feodo')['status'] === 'unavailable' && !L($m2, 'feodo')['show'] && L($m2, 'feodo')['periods']['7d']['top'] === [] && str_contains(L($m2, 'feodo')['status_text'], 'Data unavailable since 2026-11-24 19:07 UTC'), 'status: unavailable after 48 h, no numbers shown as current');
CDTM::sync_layer($st, $h, 'feodo', $T0 + 49 * 3600, true);
check(L(CDTM_View::model(CDTM::snapshot($st), $T0 + 49 * 3600 + 60), 'feodo')['status'] === 'ok', 'status: back to ok after a successful run');

/* ---------- ransomware: key, months, events ---------- */
$rs = new CDTM_Memory_Store(); $h = new FakeHttp();
check(CDTM::sync_layer($rs, $h, 'ransomware', $T0 + 20 * 60)['result'] === 'not_configured' && !$h->calls && CDTM::snapshot($rs)['layers']['ransomware']['configured'] === false, 'key: without the wp-config constant the layer is not configured and makes no request');
check(L(CDTM_View::model(CDTM::snapshot($rs), $T0), 'ransomware')['status'] === 'not_configured', 'key: page status "not configured"');
$key = 'rl-test-' . bin2hex(random_bytes(12));
define('CYBERDAT_RANSOMWARE_LIVE_API_KEY', $key);
$plan = CDTM_Source_Ransomware::plan([], $T0);
check(array_column($plan, 'id') === ['2026-09', '2026-10', '2026-11'] && str_contains($plan[2]['url'], 'year=2026&month=11&date=discovered'), 'months: first run backfills the 60-day window (3 months)');
check(array_column(CDTM_Source_Ransomware::plan(['covered_from' => gmmktime(0, 0, 0, 9, 1, 2026)], $T0), 'id') === ['2026-11'] && array_column(CDTM_Source_Ransomware::plan(['covered_from' => gmmktime(0, 0, 0, 9, 1, 2026)], gmmktime(5, 0, 0, 12, 2, 2026)), 'id') === ['2026-11', '2026-12'], 'months: then the current month, plus the previous one on days 1-2');
$h->add('api-pro.ransomware.live', $ok('[]'));
$h->add('api-pro.ransomware.live', $ok('{"victims":[]}'));
$h->add('api-pro.ransomware.live', function ($url, $headers) use ($RANSOM) {
	// identifying data in the response must never be stored
	$rows = json_decode($RANSOM, true);
	$rows[0]['victim'] = 'Acme Hospital GmbH'; $rows[0]['website'] = 'acme-hospital.example'; $rows[0]['permalink'] = 'https://www.ransomware.live/id/QWNtZQ==';
	$rows[1]['screenshot'] = 'https://images.example/leak.png'; $rows[1]['infostealer'] = ['ips' => ['198.51.100.77']]; $rows[2]['activity'] = 'acme-hospital.example';
	return ['code' => 200, 'headers' => ['etag' => 'W/"m11"'], 'body' => json_encode($rows)];
});
$res = CDTM::sync_layer($rs, $h, 'ransomware', $T0 + 20 * 60);
check($res['result'] === 'ok' && count($h->calls) === 3 && $h->calls[2]['headers']['X-API-KEY'] === $key, 'key: sent only in the X-API-KEY header');
$rsnap = CDTM::snapshot($rs);
$dump = json_encode([$rs->meta, $rs->counts]);
check(!str_contains($dump, $key) && !str_contains(json_encode($h->calls[2]['url']), $key), 'key: not stored in state, snapshot or URL');
$n7 = $rsnap['layers']['ransomware']['periods']['7d']['countries']['US']['n'] ?? 0;
$expect = count(array_filter(CDTM_Source_Ransomware::parse($RANSOM)['events'], fn($e) => $e[1] === 'US' && $e[0] >= CDTM::floor_day($T0) - 6 * 86400 && $e[0] <= $T0 + 3600));
check($n7 === $expect && $n7 > 0, "7 days: event sum per country from the source dates ($n7)");
check($rsnap['layers']['ransomware']['periods']['30d']['comparable'] === true && $rsnap['layers']['ransomware']['history_since'] === gmmktime(0, 0, 0, 9, 1, 2026), 'events: backfilled history makes 30 days comparable at once');
$b = $rsnap['layers']['ransomware']['periods']['30d']['countries']['US']['b'];
check(in_array('Healthcare', array_column($b, 0), true) && !in_array('acme-hospital.example', array_column($b, 0), true), 'events: breakdown per sector; a domain in the sector field becomes Other');
check(L(CDTM_View::model($rsnap, $T0 + 25 * 60), 'ransomware')['status'] === 'ok', 'events: layer ok after sync');
$h->add('api-pro.ransomware.live', ['error' => 'Unauthorized key ' . $key]);
CDTM::sync_layer($rs, $h, 'ransomware', $T0 + 2 * 3600 + 20 * 60);
check(!str_contains(json_encode($rs->meta), $key) && str_contains(CDTM::state($rs, 'ransomware')['last_error']['message'], '[redacted]'), 'key: redacted from error texts');

/* ---------- nothing identifying in history and snapshot ---------- */
foreach (['feodo' => $store, 'ransomware' => $rs] as $label => $s) {
	// Data only: the static layer descriptions from the code (source links, names, terms) are left out of the scan.
	$meta = array_map(static fn($v) => is_string($v) && is_array(json_decode($v, true)) ? json_decode($v, true) : $v, $s->meta);
	foreach ($meta['snapshot']['layers'] as &$layerData) $layerData = array_diff_key($layerData, array_flip(['source_url', 'terms_url', 'records_url', 'records_label', 'source', 'short', 'terms', 'name', 'metric', 'note', 'unit', 'breakdown']));
	unset($layerData);
	$all = json_encode([$meta, $s->counts], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	preg_match_all('~\b\d{1,3}(?:\.\d{1,3}){3}\b|https?://\S{0,30}|\b[a-z0-9-]+\.(?:example|com|net|org|de|live|png)\b|Acme|VICTIM-PLACEHOLDER|DOCUMENTATION-AS|group-\d~i', $all, $found);
	check($found[0] === [], "privacy ($label): no IP, URL, domain, victim, group or AS in history and snapshot" . ($found[0] ? ' — found: ' . implode(' | ', array_unique($found[0])) : ''));
}

/* ---------- server HTML ---------- */
$html = cyberdat_threat_map_render(CDTM::snapshot($rs), $T0 + 30 * 60);
check(str_contains($html, 'id="global-threat-map"') && str_contains($html, 'data-threat-map="cdtm-1"') && str_contains($html, 'Location of a server or victim does not establish attacker origin.'), 'HTML: anchor kept, attacker-origin notice');
check(str_contains($html, 'role="tablist"') && substr_count($html, 'role="tab"') === 3 && substr_count($html, 'data-cdtm-period=') === 3 && str_contains($html, 'aria-pressed="true" data-cdtm-period="7d"'), 'HTML: layer tabs and 24 h / 7 days / 30 days');
check(str_contains($html, 'Source: <a href="https://feodotracker.abuse.ch/"') && str_contains($html, 'Source: <a href="https://www.ransomware.live/"') && str_contains($html, 'https://www.ransomware.live/t&amp;c'), 'HTML: source and terms under each layer');
check(str_contains($html, 'Data unavailable: waiting for the first successful collection.') && str_contains($html, 'Updated 10 min ago (2026-11-24 19:27 UTC).'), 'HTML: per-layer status in server HTML');
check(substr_count($html, '<noscript><div class="cdtm-table">') === 1 && str_contains($html, '<caption>Top 10 countries · 7 days · reported victims</caption>'), 'HTML: server top-10 table for every layer with data (no JavaScript)');
check(!preg_match('~<(script|link|img|iframe)[^>]+(src|href)="https?://~i', $html) && !str_contains($html, '<line') && !str_contains($html, '<circle'), 'HTML: no external scripts, styles or images; no attack lines');
check(!str_contains($html, 'Acme') && preg_match('~<script type="application/json" data-cdtm-data>(.*?)</script>~s', $html, $m) && json_decode($m[1], true)['schema'] === 1 && !str_contains($m[1], '</'), 'HTML: embedded counts are valid JSON without closing tags');
$empty = cyberdat_threat_map_render(null, $T0);
check(substr_count($empty, 'Data unavailable: waiting for the first successful collection.') === 2, 'HTML: renders without a snapshot (tables not migrated): both layers waiting');
check(str_contains($empty, 'data-state="nodata"') && !str_contains($empty, '<noscript><div class="cdtm-table">'), 'HTML: no snapshot → grey map, no numbers');

echo "PASS: threat map — $passed checks, no network, database or WordPress\n";
