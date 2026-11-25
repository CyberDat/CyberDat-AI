<?php
/**
 * Global Cyber Threat Map: collector core (pure PHP, no WordPress calls).
 *
 * The store, the HTTP client and the clock are injected, so the same code runs under WP-CLI and in the offline
 * tests. Only counters are kept: per layer, per hour (48 h) and per day (60 days), per ISO country, total and
 * breakdown (family or sector). IP addresses, URLs, host names, domains and victim names are never stored.
 */
defined('ABSPATH') || exit;

interface CDTM_Store {
	public function meta_get(string $key);
	public function meta_set(string $key, $value): void;
	public function meta_delete(string $key): void;
	/** Takes the named lock unless another holder's lock is younger than $ttl seconds. */
	public function lock(string $name, int $ttl, int $now): bool;
	public function unlock(string $name): void;
	/** Deletes the layer's rows of $grain with $from <= bucket < $to, then inserts $rows [[bucket, country, dim, n], ...]. */
	public function replace_range(string $layer, string $grain, int $from, int $to, array $rows): void;
	/** Upserts $rows keeping the larger value: n = max(old, new). */
	public function upsert_max(string $layer, string $grain, array $rows): void;
	/** Rows [[bucket, country, dim, n], ...] with $from <= bucket < $to. */
	public function rows(string $layer, string $grain, int $from, int $to): array;
	public function prune(string $layer, string $grain, int $before): int;
	public function count_rows(string $layer, string $grain): int;
}

final class CDTM_Error extends RuntimeException {}

/** In-memory store with the same semantics as the database store (tests and dry runs). */
final class CDTM_Memory_Store implements CDTM_Store {
	public array $meta = [];
	public array $counts = [];
	public array $locks = [];
	public function meta_get(string $key) { return $this->meta[$key] ?? null; }
	public function meta_set(string $key, $value): void { $this->meta[$key] = $value; }
	public function meta_delete(string $key): void { unset($this->meta[$key]); }
	public function lock(string $name, int $ttl, int $now): bool {
		if (isset($this->locks[$name]) && $now - $this->locks[$name] < $ttl) return false;
		$this->locks[$name] = $now;
		return true;
	}
	public function unlock(string $name): void { unset($this->locks[$name]); }
	public function replace_range(string $layer, string $grain, int $from, int $to, array $rows): void {
		foreach ($this->counts as $k => $r) {
			if ($r[0] === $layer && $r[1] === $grain && $r[2] >= $from && $r[2] < $to) unset($this->counts[$k]);
		}
		foreach ($rows as [$bucket, $country, $dim, $n]) {
			if ($bucket < $from || $bucket >= $to) continue;
			$this->counts["$layer|$grain|$bucket|$country|$dim"] = [$layer, $grain, (int) $bucket, $country, $dim, (int) $n];
		}
	}
	public function upsert_max(string $layer, string $grain, array $rows): void {
		foreach ($rows as [$bucket, $country, $dim, $n]) {
			$k = "$layer|$grain|$bucket|$country|$dim";
			$old = $this->counts[$k][5] ?? 0;
			$this->counts[$k] = [$layer, $grain, (int) $bucket, $country, $dim, max($old, (int) $n)];
		}
	}
	public function rows(string $layer, string $grain, int $from, int $to): array {
		$out = [];
		foreach ($this->counts as $r) {
			if ($r[0] === $layer && $r[1] === $grain && $r[2] >= $from && $r[2] < $to) $out[] = [$r[2], $r[3], $r[4], $r[5]];
		}
		return $out;
	}
	public function prune(string $layer, string $grain, int $before): int {
		$n = 0;
		foreach ($this->counts as $k => $r) {
			if ($r[0] === $layer && $r[1] === $grain && $r[2] < $before) { unset($this->counts[$k]); $n++; }
		}
		return $n;
	}
	public function count_rows(string $layer, string $grain): int {
		return count(array_filter($this->counts, static fn($r) => $r[0] === $layer && $r[1] === $grain));
	}
}

/** abuse.ch Feodo Tracker: the current list of botnet C2 servers (CC0). */
final class CDTM_Source_Feodo {
	/** The dataset is generated every 5 minutes (https://feodotracker.abuse.ch/blocklist/); no faster fetch makes sense. */
	public const MIN_INTERVAL = 300;
	public const MAX_BYTES = 8388608;
	public const MAX_ITEMS = 100000;
	public const URL = 'https://feodotracker.abuse.ch/downloads/ipblocklist.json';

	public static function plan(array $state, int $now): array {
		return [['id' => 'list', 'url' => self::URL, 'headers' => []]];
	}

	/** @return array{countries: array<string, array{n:int, b:array<string,int>}>, items:int} */
	public static function parse(string $body): array {
		$data = json_decode($body, true, 16);
		if (!is_array($data) || !array_is_list($data)) throw new CDTM_Error('format: expected a JSON array');
		if (count($data) > self::MAX_ITEMS) throw new CDTM_Error('format: too many entries');
		$countries = [];
		foreach ($data as $item) {
			if (!is_array($item) || !array_key_exists('ip_address', $item) || !array_key_exists('country', $item) || !array_key_exists('malware', $item)) {
				throw new CDTM_Error('format: entry without ip_address, country or malware');
			}
			if (!is_string($item['ip_address']) || filter_var($item['ip_address'], FILTER_VALIDATE_IP) === false) {
				throw new CDTM_Error('format: entry with an invalid ip_address');
			}
			$cc = CDTM::country($item['country']);
			$family = CDTM::label($item['malware'], 'Unknown family');
			$countries[$cc]['n'] = ($countries[$cc]['n'] ?? 0) + 1;
			$countries[$cc]['b'][$family] = ($countries[$cc]['b'][$family] ?? 0) + 1;
		}
		return ['countries' => $countries, 'items' => count($data)];
	}

	/** A gauge: the hour keeps the latest list, the day keeps the largest hourly value (per country and breakdown). */
	public static function apply(CDTM_Store $store, array $parsed, int $now): void {
		$hour = CDTM::floor_hour($now);
		$day = CDTM::floor_day($now);
		$hourly = CDTM::rows_of($parsed['countries'], $hour);
		$store->replace_range('feodo', 'h', $hour, $hour + 3600, $hourly);
		$store->upsert_max('feodo', 'd', CDTM::rows_of($parsed['countries'], $day));
	}
}

/** Ransomware.live API PRO: victims discovered per month (free personal key, attribution required). */
final class CDTM_Source_Ransomware {
	/** Ransomware.live caches its data for 30 minutes; polling faster is a fair-use breach (https://www.ransomware.live/t&c). */
	public const MIN_INTERVAL = 1800;
	public const MAX_BYTES = 16777216;
	public const MAX_ITEMS = 20000;
	public const BASE = 'https://api-pro.ransomware.live/victims/';
	public const KEY_CONSTANT = 'CYBERDAT_RANSOMWARE_LIVE_API_KEY';

	/** Months to fetch: the current one; older ones while the 60-day history is not covered, and on days 1-2. */
	public static function plan(array $state, int $now): array {
		$need_from = CDTM::floor_day($now) - (CDTM::DAILY_DAYS - 1) * 86400;
		$covered = $state['covered_from'] ?? null;
		$months = [];
		$first = (!is_int($covered) || $covered > $need_from) ? $need_from : ((int) gmdate('j', $now) <= 2 ? CDTM::month_start($now) - 86400 : $now);
		for ($m = CDTM::month_start($first); $m <= $now; $m = CDTM::next_month($m)) $months[] = $m;
		return array_map(static fn($m) => [
			'id' => gmdate('Y-m', $m),
			'url' => self::BASE . '?' . http_build_query(['year' => gmdate('Y', $m), 'month' => gmdate('m', $m), 'date' => 'discovered']),
			'headers' => [],
			'month' => $m,
		], $months);
	}

	/** @return array{events: list<array{0:int,1:string,2:string,3:bool}>, items:int} [timestamp, country, sector, has_time] */
	public static function parse(string $body): array {
		$data = json_decode($body, true, 64);
		if (is_array($data) && !array_is_list($data)) {
			foreach (['victims', 'data', 'results'] as $key) {
				if (isset($data[$key]) && is_array($data[$key]) && array_is_list($data[$key])) { $data = $data[$key]; break; }
			}
		}
		if (!is_array($data) || !array_is_list($data)) throw new CDTM_Error('format: expected a JSON list of victims');
		if (count($data) > self::MAX_ITEMS) throw new CDTM_Error('format: too many entries');
		$events = [];
		$bad = 0;
		foreach ($data as $item) {
			$when = is_array($item) ? CDTM::parse_time($item['discovered'] ?? null) : null;
			if ($when === null) { $bad++; continue; }
			$events[] = [$when[0], CDTM::country($item['country'] ?? null), CDTM::label($item['activity'] ?? null, 'Not specified'), $when[1]];
		}
		if ($data && $bad * 2 > count($data)) throw new CDTM_Error('format: most entries have no discovered date');
		return ['events' => $events, 'items' => count($data)];
	}

	/** Events: every fetched month replaces its own days (within 60 days) and hours (within 48 h). */
	public static function apply(CDTM_Store $store, array $parsed_by_month, int $now): void {
		$keep_d = CDTM::floor_day($now) - (CDTM::DAILY_DAYS - 1) * 86400;
		$keep_h = CDTM::floor_hour($now) - (CDTM::HOURLY_HOURS - 1) * 3600;
		foreach ($parsed_by_month as $month => $parsed) {
			$end = CDTM::next_month($month);
			$days = [];
			$hours = [];
			foreach ($parsed['events'] as [$ts, $cc, $sector, $has_time]) {
				if ($ts < $month || $ts >= $end || $ts > $now + 3600) continue;
				$d = CDTM::floor_day($ts);
				$days[$d][$cc]['n'] = ($days[$d][$cc]['n'] ?? 0) + 1;
				$days[$d][$cc]['b'][$sector] = ($days[$d][$cc]['b'][$sector] ?? 0) + 1;
				if ($has_time) {
					$h = CDTM::floor_hour($ts);
					$hours[$h][$cc]['n'] = ($hours[$h][$cc]['n'] ?? 0) + 1;
					$hours[$h][$cc]['b'][$sector] = ($hours[$h][$cc]['b'][$sector] ?? 0) + 1;
				}
			}
			$drows = [];
			foreach ($days as $d => $countries) array_push($drows, ...CDTM::rows_of($countries, $d));
			$hrows = [];
			foreach ($hours as $h => $countries) array_push($hrows, ...CDTM::rows_of($countries, $h));
			$store->replace_range('ransomware', 'd', max($month, $keep_d), min($end, CDTM::floor_day($now) + 86400), $drows);
			$store->replace_range('ransomware', 'h', max($month, $keep_h), min($end, CDTM::floor_hour($now) + 3600), $hrows);
		}
	}
}

final class CDTM {
	public const SCHEMA = 1;
	public const TIMEOUT = 20;
	public const STALE_AFTER = 10800;        // 3 h
	public const UNAVAILABLE_AFTER = 172800; // 48 h
	public const HOURLY_HOURS = 48;
	public const DAILY_DAYS = 60;
	public const LOCK_TTL = 900;
	public const DUE_AFTER = 3300;           // a regular run: at least 55 min after the previous attempt, inside the slot
	public const CATCHUP_AFTER = 7200;       // a missed slot is caught up by any run 2 h after the previous attempt
	public const SLOT_MINUTES = 20;
	public const MAX_BREAKDOWN = 8;
	public const UNKNOWN = 'ZZ';
	public const PERIODS = ['24h' => ['h', 24, 3600], '7d' => ['d', 7, 86400], '30d' => ['d', 30, 86400]];

	public static function layers(): array {
		return [
			'feodo' => [
				'id' => 'feodo', 'source_class' => CDTM_Source_Feodo::class, 'kind' => 'gauge', 'slot' => 7,
				'min_interval' => CDTM_Source_Feodo::MIN_INTERVAL, 'max_bytes' => CDTM_Source_Feodo::MAX_BYTES, 'key_constant' => null,
				'hosts' => ['feodotracker.abuse.ch'],
				'name' => 'Botnet C2 servers', 'source' => 'abuse.ch Feodo Tracker', 'short' => 'Feodo Tracker',
				'unit' => 'C2 servers listed', 'breakdown' => 'Malware families',
				'metric' => 'Peak number of listed botnet command-and-control servers per country in the period. The source publishes only its current list, so CyberDat keeps its own hourly history.',
				'note' => 'Country where the command-and-control server is hosted, as reported by the source.',
				'source_url' => 'https://feodotracker.abuse.ch/', 'terms_url' => 'https://abuse.ch/terms-of-use/',
				'terms' => 'License: CC0; provided as is on a best-effort basis.',
				'records_url' => 'https://feodotracker.abuse.ch/browse/', 'records_label' => 'Browse Feodo Tracker records (the source has no country filter)',
			],
			'ransomware' => [
				'id' => 'ransomware', 'source_class' => CDTM_Source_Ransomware::class, 'kind' => 'event', 'slot' => 27,
				'min_interval' => CDTM_Source_Ransomware::MIN_INTERVAL, 'max_bytes' => CDTM_Source_Ransomware::MAX_BYTES, 'key_constant' => CDTM_Source_Ransomware::KEY_CONSTANT,
				'hosts' => ['api-pro.ransomware.live'],
				'name' => 'Ransomware victims', 'source' => 'Ransomware.live', 'short' => 'Ransomware.live',
				'unit' => 'reported victims', 'breakdown' => 'Sectors',
				'metric' => 'Victims listed on ransomware leak sites and first seen by Ransomware.live in the period, by the country given for the victim.',
				'note' => 'Country of the reported victim. Totals only, no victim names. A listing is a claim by a ransomware group, not a confirmed incident.',
				'source_url' => 'https://www.ransomware.live/', 'terms_url' => 'https://www.ransomware.live/t&c',
				'terms' => 'Used under its terms with attribution; inclusion does not confirm that a claimed attack occurred.',
				'records_url' => 'https://www.ransomware.live/country/{CC}', 'records_label' => 'Open the country page on Ransomware.live',
			],
		];
	}

	/* ---------- small helpers ---------- */

	public static function floor_hour(int $t): int { return intdiv($t, 3600) * 3600; }
	public static function floor_day(int $t): int { return intdiv($t, 86400) * 86400; }
	public static function month_start(int $t): int { return gmmktime(0, 0, 0, (int) gmdate('n', $t), 1, (int) gmdate('Y', $t)); }
	public static function next_month(int $m): int { return gmmktime(0, 0, 0, (int) gmdate('n', $m) + 1, 1, (int) gmdate('Y', $m)); }

	public static function country($value): string {
		$cc = is_string($value) ? strtoupper(trim($value)) : '';
		return preg_match('/^[A-Z]{2}$/', $cc) && $cc !== 'ZZ' ? $cc : self::UNKNOWN;
	}

	/**
	 * A family or sector label: letters, digits, spaces and & + - / ( ) , only (no dot, colon or @), so never a URL,
	 * domain, IP or e-mail. Placeholders of the source ("Not Found", "Unknown", "N/A") become the fallback.
	 */
	public static function label($value, string $fallback): string {
		if (!is_string($value)) return $fallback;
		$v = trim(preg_replace('/\s+/u', ' ', $value) ?? '');
		if ($v === '' || in_array(strtolower($v), ['not found', 'unknown', 'n/a', 'none', 'null', '-'], true)) return $fallback;
		if (preg_match_all('/./su', $v) > 48 || !preg_match('/^[\p{L}\p{N}][\p{L}\p{N} &+\/,()\-]*$/u', $v)) return 'Other';
		return $v;
	}

	/** "2026-11-24 10:12:33.123", "2026-11-24T10:12:33Z" or "2026-11-24" (UTC) → [timestamp, has_time]. */
	public static function parse_time($value): ?array {
		if (!is_string($value) || !preg_match('/^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?(?:Z|[+-]00:?00)?)?$/', trim($value), $m)) return null;
		if (!checkdate((int) $m[2], (int) $m[3], (int) $m[1])) return null;
		$has_time = isset($m[4]) && $m[4] !== '';
		$t = gmmktime($has_time ? (int) $m[4] : 0, $has_time ? (int) $m[5] : 0, $has_time && isset($m[6]) && $m[6] !== '' ? (int) $m[6] : 0, (int) $m[2], (int) $m[3], (int) $m[1]);
		return [$t, $has_time];
	}

	/** countries [CC => [n, b => [label => n]]] → rows [[bucket, CC, '', n], [bucket, CC, label, n], ...] */
	public static function rows_of(array $countries, int $bucket): array {
		$rows = [];
		foreach ($countries as $cc => $c) {
			$rows[] = [$bucket, $cc, '', (int) $c['n']];
			foreach ($c['b'] ?? [] as $label => $n) $rows[] = [$bucket, $cc, (string) $label, (int) $n];
		}
		return $rows;
	}

	/** Error text for the status: no keys, no URLs with parameters (host only), no control characters, short. */
	public static function clean_error(string $message, array $secrets = []): string {
		foreach ($secrets as $s) if (is_string($s) && $s !== '') $message = str_replace($s, '[redacted]', $message);
		$message = preg_replace('~https?://([^/\s?#:]+)[^\s]*~i', '$1', $message) ?? '';
		$message = preg_replace('/[\x00-\x1F\x7F]+/', ' ', $message) ?? '';
		return self::cut(trim($message), 200);
	}

	/** First $n characters of UTF-8 text (no mbstring needed). */
	public static function cut(string $s, int $n): string {
		return preg_match('/^.{0,' . $n . '}/su', $s, $m) ? $m[0] : substr($s, 0, $n);
	}

	public static function key_for(array $layer): ?string {
		$c = $layer['key_constant'];
		if ($c === null) return null;
		return defined($c) && is_string(constant($c)) && trim(constant($c)) !== '' ? trim(constant($c)) : '';
	}

	public static function configured(array $layer): bool { return $layer['key_constant'] === null || self::key_for($layer) !== ''; }

	public static function state(CDTM_Store $store, string $id): array {
		$s = $store->meta_get('state:' . $id);
		$s = is_string($s) ? json_decode($s, true) : null;
		return is_array($s) ? $s : [];
	}

	public static function save_state(CDTM_Store $store, string $id, array $state): void {
		$store->meta_set('state:' . $id, json_encode($state, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
	}

	/** ok (≤ 3 h), stale (≤ 48 h), unavailable (older or never), not_configured (no key). */
	public static function freshness(array $state, int $now, bool $configured = true): string {
		if (!$configured) return 'not_configured';
		$last = $state['last_success'] ?? null;
		if (!is_int($last)) return 'unavailable';
		$age = $now - $last;
		return $age <= self::STALE_AFTER ? 'ok' : ($age <= self::UNAVAILABLE_AFTER ? 'stale' : 'unavailable');
	}

	/** A regular run happens inside the layer's slot (minute slot..slot+19) at least 55 min after the last attempt. */
	public static function due(array $layer, array $state, int $now): bool {
		$last = $state['last_attempt'] ?? null;
		if (!is_int($last)) return true;
		$since = $now - $last;
		if ($since >= self::CATCHUP_AFTER) return true;
		$minute = intdiv($now % 3600, 60);
		return $since >= self::DUE_AFTER && $minute >= $layer['slot'] && $minute < $layer['slot'] + self::SLOT_MINUTES;
	}

	/* ---------- HTTP ---------- */

	/**
	 * $http(url, headers, max_bytes, timeout) returns ['code' => int, 'headers' => [lowercase => value], 'body' => string]
	 * or ['error' => string]. The response is checked here: HTTPS on an allowed host, status, size, body.
	 */
	private static function get(callable $http, array $layer, array $request, array $validators, ?string $key): array {
		$parts = parse_url($request['url']);
		if (($parts['scheme'] ?? '') !== 'https' || !in_array($parts['host'] ?? '', $layer['hosts'], true)) throw new CDTM_Error('blocked: not an allowed HTTPS source');
		$headers = $request['headers'] + ['Accept' => 'application/json'];
		if ($key !== null) $headers['X-API-KEY'] = $key;
		if (!empty($validators['etag'])) $headers['If-None-Match'] = $validators['etag'];
		if (!empty($validators['last_modified'])) $headers['If-Modified-Since'] = $validators['last_modified'];
		$response = $http($request['url'], $headers, $layer['max_bytes'], self::TIMEOUT);
		if (isset($response['error'])) throw new CDTM_Error('network: ' . $response['error']);
		$code = (int) ($response['code'] ?? 0);
		if ($code === 304) return ['not_modified' => true, 'validators' => $validators];
		if ($code !== 200) throw new CDTM_Error('HTTP ' . $code . ' from ' . $parts['host']);
		$length = $response['headers']['content-length'] ?? '';
		$body = (string) ($response['body'] ?? '');
		if ((is_numeric($length) && (int) $length > $layer['max_bytes']) || strlen($body) > $layer['max_bytes']) throw new CDTM_Error('size: response larger than ' . $layer['max_bytes'] . ' bytes');
		if ($body === '') throw new CDTM_Error('format: empty response');
		return ['body' => $body, 'validators' => [
			'etag' => is_string($response['headers']['etag'] ?? null) ? substr($response['headers']['etag'], 0, 200) : '',
			'last_modified' => is_string($response['headers']['last-modified'] ?? null) ? substr($response['headers']['last-modified'], 0, 64) : '',
		]];
	}

	/* ---------- sync ---------- */

	/**
	 * One layer. Returns ['result' => ok|not_modified|skipped|error|not_configured, 'message' => string].
	 * On any error nothing is written to the history and the last good snapshot stays.
	 */
	public static function sync_layer(CDTM_Store $store, callable $http, string $id, int $now, bool $force = false): array {
		$layers = self::layers();
		if (!isset($layers[$id])) return ['result' => 'error', 'message' => 'unknown layer'];
		$layer = $layers[$id];
		$state = self::state($store, $id);
		$key = self::key_for($layer);
		if ($key === '') {
			$state['status'] = 'not_configured';
			self::save_state($store, $id, $state);
			self::rebuild_snapshot($store, $now);
			return ['result' => 'not_configured', 'message' => 'constant ' . $layer['key_constant'] . ' is not set'];
		}
		$last = $state['last_attempt'] ?? null;
		if (is_int($last) && $now - $last < $layer['min_interval']) {
			return ['result' => 'skipped', 'message' => 'MIN_INTERVAL ' . $layer['min_interval'] . ' s not reached (' . ($now - $last) . ' s since the last request)'];
		}
		if (!$force && !self::due($layer, $state, $now)) return ['result' => 'skipped', 'message' => 'not due (slot :' . sprintf('%02d', $layer['slot']) . ')'];
		if (!$store->lock('sync:' . $id, self::LOCK_TTL, $now)) return ['result' => 'skipped', 'message' => 'another sync holds the lock'];
		try {
			$state['last_attempt'] = $now;
			self::save_state($store, $id, $state);
			$class = $layer['source_class'];
			$parsed = [];
			$validators = $state['validators'] ?? [];
			$modified = false;
			foreach ($class::plan($state, $now) as $request) {
				$r = self::get($http, $layer, $request, $validators[$request['id']] ?? [], $key);
				$validators[$request['id']] = $r['validators'];
				if (!empty($r['not_modified'])) {
					if ($id === 'feodo') $parsed[$request['id']] = ['countries' => $state['last_counts'] ?? [], 'items' => $state['last_items'] ?? 0];
					continue;
				}
				$modified = true;
				$parsed[$request['month'] ?? $request['id']] = $class::parse($r['body']);
				unset($r);
			}
			if ($id === 'feodo') {
				$list = $parsed['list'] ?? ['countries' => [], 'items' => 0];
				CDTM_Source_Feodo::apply($store, $list, $now);
				$state['last_counts'] = $list['countries'];
				$state['last_items'] = $list['items'];
				$state['history_since'] = $state['history_since'] ?? $now;
			} else {
				CDTM_Source_Ransomware::apply($store, $parsed, $now);
				$fetched = array_keys($parsed);
				if ($fetched) $state['covered_from'] = min(array_merge([$state['covered_from'] ?? PHP_INT_MAX], $fetched));
				$state['history_since'] = $state['covered_from'] ?? $now;
				$state['last_items'] = array_sum(array_map(static fn($p) => $p['items'], $parsed));
			}
			$store->prune($id, 'h', self::floor_hour($now) - (self::HOURLY_HOURS - 1) * 3600);
			$store->prune($id, 'd', self::floor_day($now) - (self::DAILY_DAYS - 1) * 86400);
			$state['validators'] = $validators;
			$state['last_success'] = $now;
			$state['status'] = 'ok';
			$state['last_error'] = null;
			$state['runs'] = ($state['runs'] ?? 0) + 1;
			self::save_state($store, $id, $state);
			self::rebuild_snapshot($store, $now);
			return ['result' => $modified ? 'ok' : 'not_modified', 'message' => $modified ? 'updated' : '304 not modified'];
		} catch (Throwable $e) {
			$state['status'] = 'error';
			$state['last_error'] = ['at' => $now, 'message' => self::clean_error($e->getMessage(), [$key])];
			self::save_state($store, $id, $state);
			self::rebuild_snapshot($store, $now);
			return ['result' => 'error', 'message' => $state['last_error']['message']];
		} finally {
			$store->unlock('sync:' . $id);
		}
	}

	/* ---------- snapshot ---------- */

	public static function country_names(): array {
		static $names = null;
		if ($names === null) {
			$file = dirname(__DIR__, 2) . '/assets/maps/iso3166-1.json';
			$data = is_file($file) ? json_decode((string) file_get_contents($file), true) : null;
			$names = [];
			foreach ($data['countries'] ?? [] as $c) $names[$c[0]] = $c[2];
		}
		return $names;
	}

	/** Aggregates one period: sum for events, max for the gauge, per country and per breakdown label. */
	public static function period(CDTM_Store $store, array $layer, array $state, string $period, int $now): array {
		[$grain, $len, $unit] = self::PERIODS[$period];
		$end = ($grain === 'h' ? self::floor_hour($now) : self::floor_day($now)) + $unit;
		$start = $end - $len * $unit;
		$prev_start = $start - $len * $unit;
		$since = $state['history_since'] ?? null;
		$complete = is_int($since) && $since <= $start;
		$comparable = is_int($since) && $since <= $prev_start;
		$agg = static function (array $rows, string $kind): array {
			$out = [];
			foreach ($rows as [$bucket, $cc, $dim, $n]) {
				$k = $dim === '' ? 'n' : $dim;
				if ($kind === 'gauge') {
					if ($k === 'n') $out[$cc]['n'] = max($out[$cc]['n'] ?? 0, $n); else $out[$cc]['b'][$k] = max($out[$cc]['b'][$k] ?? 0, $n);
				} elseif ($k === 'n') $out[$cc]['n'] = ($out[$cc]['n'] ?? 0) + $n; else $out[$cc]['b'][$k] = ($out[$cc]['b'][$k] ?? 0) + $n;
			}
			return $out;
		};
		$cur = $agg($store->rows($layer['id'], $grain, $start, $end), $layer['kind']);
		$prev = $comparable ? $agg($store->rows($layer['id'], $grain, $prev_start, $start), $layer['kind']) : [];
		$countries = [];
		foreach (array_unique(array_merge(array_keys($cur), array_keys($prev))) as $cc) {
			if ($cc === self::UNKNOWN) continue;
			$n = (int) ($cur[$cc]['n'] ?? 0);
			$b = $cur[$cc]['b'] ?? [];
			arsort($b);
			$top = array_slice($b, 0, self::MAX_BREAKDOWN, true);
			$rest = array_sum(array_slice($b, self::MAX_BREAKDOWN));
			$row = ['n' => $n, 'b' => array_map(null, array_keys($top), array_values($top))];
			if ($rest > 0) {
				$at = array_search('Other', array_column($row['b'], 0), true);
				if ($at === false) $row['b'][] = ['Other', $rest]; else $row['b'][$at][1] += $rest;
			}
			if ($comparable) $row['prev'] = (int) ($prev[$cc]['n'] ?? 0);
			if ($n > 0 || $comparable) $countries[$cc] = $row;
		}
		uksort($countries, static fn($a, $b) => [$countries[$b]['n'], $a] <=> [$countries[$a]['n'], $b]);
		return [
			'from' => $start, 'to' => $end, 'complete' => $complete, 'comparable' => $comparable,
			'unknown' => (int) ($cur[self::UNKNOWN]['n'] ?? 0),
			'total' => array_sum(array_column($countries, 'n')),
			'countries' => $countries,
		];
	}

	public static function rebuild_snapshot(CDTM_Store $store, int $now): array {
		$names = self::country_names();
		$out = ['schema' => self::SCHEMA, 'generated_at' => $now, 'layers' => [], 'names' => []];
		foreach (self::layers() as $id => $layer) {
			$state = self::state($store, $id);
			$public = array_intersect_key($layer, array_flip(['id', 'kind', 'name', 'source', 'short', 'unit', 'breakdown', 'metric', 'note', 'source_url', 'terms_url', 'terms', 'records_url', 'records_label']));
			$public += [
				'configured' => self::configured($layer),
				'last_success' => $state['last_success'] ?? null,
				'last_attempt' => $state['last_attempt'] ?? null,
				'history_since' => $state['history_since'] ?? null,
				// The page only says that the last attempt failed; the error text stays in `wp cyberdat threatmap status`.
				'last_error_at' => ($state['status'] ?? '') === 'error' ? ($state['last_error']['at'] ?? null) : null,
				'periods' => [],
			];
			if (is_int($public['last_success'])) {
				foreach (array_keys(self::PERIODS) as $p) {
					$public['periods'][$p] = self::period($store, $layer, $state, $p, $now);
					foreach (array_keys($public['periods'][$p]['countries']) as $cc) $out['names'][$cc] = $names[$cc] ?? $cc;
				}
			}
			$out['layers'][$id] = $public;
		}
		ksort($out['names']);
		$store->meta_set('snapshot', json_encode($out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
		return $out;
	}

	public static function snapshot(CDTM_Store $store): ?array {
		$s = $store->meta_get('snapshot');
		$s = is_string($s) ? json_decode($s, true) : null;
		return is_array($s) && ($s['schema'] ?? null) === self::SCHEMA ? $s : null;
	}

	/** One row per layer for `wp cyberdat threatmap status`. */
	public static function status_rows(CDTM_Store $store, int $now): array {
		$rows = [];
		foreach (self::layers() as $id => $layer) {
			$s = self::state($store, $id);
			$fmt = static fn($t) => is_int($t) ? gmdate('Y-m-d H:i', $t) . ' UTC' : '-';
			$rows[] = [
				'layer' => $id,
				'source' => $layer['source'],
				'freshness' => self::freshness($s, $now, self::configured($layer)),
				'last_run' => $s['status'] ?? '-',
				'last_success' => $fmt($s['last_success'] ?? null),
				'last_attempt' => $fmt($s['last_attempt'] ?? null),
				'successful_runs' => (string) ($s['runs'] ?? 0),
				'error' => $s['last_error']['message'] ?? '-',
				'history' => $store->count_rows($id, 'h') . ' hourly rows / ' . $store->count_rows($id, 'd') . ' daily rows',
				'history_since' => $fmt($s['history_since'] ?? null),
				'min_interval' => $layer['min_interval'] . ' s',
			];
		}
		return $rows;
	}
}
