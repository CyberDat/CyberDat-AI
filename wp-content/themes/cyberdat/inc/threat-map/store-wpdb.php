<?php
/**
 * Global Cyber Threat Map: database store in two theme tables, {prefix}cdtm_counts and {prefix}cdtm_meta.
 * Created by `wp cyberdat threatmap migrate`, removed by `wp cyberdat threatmap uninstall --yes` (rollback).
 * The tables are not reachable over the web, unlike files in uploads, and hold counters and collector state only.
 */
defined('ABSPATH') || exit;

final class CDTM_Wpdb_Store implements CDTM_Store {
	public const SCHEMA_VERSION = 1;
	private $db;
	private string $counts;
	private string $meta;

	public function __construct($wpdb = null) {
		$this->db = $wpdb ?? ($GLOBALS['wpdb'] ?? null);
		if (!is_object($this->db) || !isset($this->db->prefix)) throw new CDTM_Error('database: WordPress database is not available');
		$this->counts = $this->db->prefix . 'cdtm_counts';
		$this->meta = $this->db->prefix . 'cdtm_meta';
	}

	public function tables(): array { return [$this->counts, $this->meta]; }

	public function installed(): bool {
		$quiet = $this->db->suppress_errors(true);
		$ok = true;
		foreach ($this->tables() as $t) {
			$ok = $ok && $this->db->get_var($this->db->prepare('SHOW TABLES LIKE %s', $this->db->esc_like($t))) === $t;
		}
		$this->db->suppress_errors($quiet);
		return $ok;
	}

	public function install(): void {
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset = $this->db->get_charset_collate();
		dbDelta("CREATE TABLE {$this->counts} (
  layer varchar(24) NOT NULL,
  grain char(1) NOT NULL,
  bucket int(10) unsigned NOT NULL,
  country char(2) NOT NULL,
  dim varchar(64) NOT NULL DEFAULT '',
  n int(10) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY  (layer,grain,bucket,country,dim),
  KEY layer_grain_bucket (layer,grain,bucket)
) $charset;");
		dbDelta("CREATE TABLE {$this->meta} (
  k varchar(64) NOT NULL,
  v longtext NOT NULL,
  updated int(10) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY  (k)
) $charset;");
		if (!$this->installed()) throw new CDTM_Error('migration failed: tables not created');
		$this->meta_set('schema_version', (string) self::SCHEMA_VERSION);
	}

	public function uninstall(): void {
		foreach ($this->tables() as $t) $this->db->query("DROP TABLE IF EXISTS `$t`");
	}

	public function meta_get(string $key) {
		$quiet = $this->db->suppress_errors(true);
		$v = $this->db->get_var($this->db->prepare("SELECT v FROM {$this->meta} WHERE k = %s", $key));
		$this->db->suppress_errors($quiet);
		return $v;
	}

	public function meta_set(string $key, $value): void {
		$this->must($this->db->query($this->db->prepare(
			"INSERT INTO {$this->meta} (k, v, updated) VALUES (%s, %s, %d) ON DUPLICATE KEY UPDATE v = VALUES(v), updated = VALUES(updated)",
			$key, (string) $value, time()
		)));
	}

	public function meta_delete(string $key): void {
		$this->db->query($this->db->prepare("DELETE FROM {$this->meta} WHERE k = %s", $key));
	}

	public function lock(string $name, int $ttl, int $now): bool {
		$k = 'lock:' . $name;
		$taken = $this->db->query($this->db->prepare("INSERT IGNORE INTO {$this->meta} (k, v, updated) VALUES (%s, %s, %d)", $k, (string) $now, $now));
		if ($taken === 1) return true;
		// A lock older than its TTL belongs to a crashed run and is taken over atomically.
		return $this->db->query($this->db->prepare("UPDATE {$this->meta} SET v = %s, updated = %d WHERE k = %s AND updated < %d", (string) $now, $now, $k, $now - $ttl)) === 1;
	}

	public function unlock(string $name): void { $this->meta_delete('lock:' . $name); }

	public function replace_range(string $layer, string $grain, int $from, int $to, array $rows): void {
		if ($to <= $from) return;
		$this->db->query('START TRANSACTION');
		try {
			$this->must($this->db->query($this->db->prepare("DELETE FROM {$this->counts} WHERE layer = %s AND grain = %s AND bucket >= %d AND bucket < %d", $layer, $grain, $from, $to)));
			$this->insert($layer, $grain, array_values(array_filter($rows, static fn($r) => $r[0] >= $from && $r[0] < $to)), false);
			$this->db->query('COMMIT');
		} catch (Throwable $e) {
			$this->db->query('ROLLBACK');
			throw $e;
		}
	}

	public function upsert_max(string $layer, string $grain, array $rows): void { $this->insert($layer, $grain, $rows, true); }

	private function insert(string $layer, string $grain, array $rows, bool $max): void {
		foreach (array_chunk($rows, 400) as $chunk) {
			$values = [];
			foreach ($chunk as [$bucket, $country, $dim, $n]) {
				$values[] = $this->db->prepare('(%s, %s, %d, %s, %s, %d)', $layer, $grain, $bucket, $country, CDTM::cut((string) $dim, 64), $n);
			}
			$sql = "INSERT INTO {$this->counts} (layer, grain, bucket, country, dim, n) VALUES " . implode(',', $values)
				. ($max ? ' ON DUPLICATE KEY UPDATE n = GREATEST(n, VALUES(n))' : ' ON DUPLICATE KEY UPDATE n = VALUES(n)');
			$this->must($this->db->query($sql));
		}
	}

	public function rows(string $layer, string $grain, int $from, int $to): array {
		$r = $this->db->get_results($this->db->prepare(
			"SELECT bucket, country, dim, n FROM {$this->counts} WHERE layer = %s AND grain = %s AND bucket >= %d AND bucket < %d",
			$layer, $grain, $from, $to
		), ARRAY_N);
		return array_map(static fn($x) => [(int) $x[0], (string) $x[1], (string) $x[2], (int) $x[3]], $r ?: []);
	}

	public function prune(string $layer, string $grain, int $before): int {
		return (int) $this->db->query($this->db->prepare("DELETE FROM {$this->counts} WHERE layer = %s AND grain = %s AND bucket < %d", $layer, $grain, $before));
	}

	public function count_rows(string $layer, string $grain): int {
		return (int) $this->db->get_var($this->db->prepare("SELECT COUNT(*) FROM {$this->counts} WHERE layer = %s AND grain = %s", $layer, $grain));
	}

	private function must($result): void {
		if ($result === false) throw new CDTM_Error('database: ' . CDTM::clean_error((string) $this->db->last_error));
	}
}

/** WordPress HTTP API client: HTTPS only (checked by the core), 20 s timeout, no redirects, size limit + 1 byte. */
function cdtm_http(string $url, array $headers, int $max_bytes, int $timeout): array {
	$r = wp_safe_remote_get($url, [
		'timeout' => $timeout,
		'redirection' => 0,
		'limit_response_size' => $max_bytes + 1,
		'headers' => $headers,
		'user-agent' => 'CyberDat-ThreatMap/1.0',
		'reject_unsafe_urls' => true,
		'sslverify' => true,
	]);
	if (is_wp_error($r)) {
		$message = $r->get_error_message();
		// wp_safe_remote_get() reports a host it cannot resolve (or one on a private address) as an invalid URL.
		if ($message === 'A valid URL was not provided.') $message = 'host could not be resolved or is not a public address';
		return ['error' => $message];
	}
	$h = [];
	foreach (['content-length', 'etag', 'last-modified'] as $name) {
		$v = wp_remote_retrieve_header($r, $name);
		if (is_array($v)) $v = end($v);
		if (is_string($v) && $v !== '') $h[$name] = $v;
	}
	return ['code' => (int) wp_remote_retrieve_response_code($r), 'headers' => $h, 'body' => (string) wp_remote_retrieve_body($r)];
}
