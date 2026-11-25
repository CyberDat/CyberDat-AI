<?php
/**
 * Threat map database store against a real WordPress + MariaDB (run by tests/threat-map-wp-integration.sh with
 * `wp eval-file`). Uses its own table prefix copy-free: the real {prefix}cdtm_* tables of a disposable install.
 * The HTTP client is a fake; nothing leaves the machine.
 */
defined('ABSPATH') || exit;
if (!defined('WP_CLI') || !WP_CLI) exit;

$n = 0;
$check = static function ($ok, string $label) use (&$n) { if (!$ok) WP_CLI::error('FAIL: ' . $label); $n++; WP_CLI::log('PASS: ' . $label); };
global $wpdb;
$store = new CDTM_Wpdb_Store();
$check($store->installed(), 'tables exist after migrate: ' . implode(', ', $store->tables()));
$cols = $wpdb->get_col("SHOW COLUMNS FROM {$wpdb->prefix}cdtm_counts");
$check($cols === ['layer', 'grain', 'bucket', 'country', 'dim', 'n'], 'counts table holds counters only: ' . implode(',', $cols));
$check($store->meta_get('schema_version') === '1', 'schema version recorded');

// lock: atomic insert, refused while held, taken over after the TTL
$check($store->lock('it', 900, 1000) && !$store->lock('it', 900, 1500) && $store->lock('it', 900, 1901), 'lock: held, refused, taken over after 900 s');
$store->unlock('it');
$check($store->lock('it', 900, 2000), 'lock: free again after unlock');
$store->unlock('it');

// counts: replace a range, keep the maximum, read, prune
$store->replace_range('it', 'h', 0, 7200, [[0, 'US', '', 3], [0, 'US', 'QakBot', 3], [3600, 'DE', '', 1], [9999, 'FR', '', 9]]);
$check(count($store->rows('it', 'h', 0, 7200)) === 3 && !$store->rows('it', 'h', 7200, 20000), 'replace_range: rows outside the range ignored');
$store->replace_range('it', 'h', 0, 3600, [[0, 'US', '', 1]]);
$check($store->rows('it', 'h', 0, 3600) === [[0, 'US', '', 1]], 'replace_range: the range is replaced, not merged');
$store->upsert_max('it', 'd', [[0, 'US', '', 2]]);
$store->upsert_max('it', 'd', [[0, 'US', '', 1]]);
$store->upsert_max('it', 'd', [[0, 'US', '', 5]]);
$check($store->rows('it', 'd', 0, 1) === [[0, 'US', '', 5]], 'upsert_max: keeps the largest value');
$check($store->prune('it', 'h', 0) === 0 && $store->prune('it', 'h', 3600) === 1 && $store->count_rows('it', 'h') === 1 && $store->prune('it', 'h', 3601) === 1 && $store->count_rows('it', 'h') === 0, 'prune: deletes only buckets older than the limit');
$store->prune('it', 'd', PHP_INT_MAX);

// a full sync through the real tables with a fake HTTP client
$fixture = (string) file_get_contents(getenv('CDTM_FIXTURE') ?: '/fixtures/feodo-ipblocklist.json');
$t = gmmktime(19, 7, 0, 11, 24, 2026);
$http = static function ($url, $headers) use ($fixture) {
	return isset($headers['If-None-Match']) ? ['code' => 304, 'headers' => [], 'body' => ''] : ['code' => 200, 'headers' => ['etag' => '"it1"'], 'body' => $fixture];
};
$store->meta_delete('state:feodo');
$r1 = CDTM::sync_layer($store, $http, 'feodo', $t);
$r2 = CDTM::sync_layer($store, $http, 'feodo', $t + 3600);
$check($r1['result'] === 'ok' && $r2['result'] === 'not_modified', 'sync on MariaDB: 200 then 304');
$snap = CDTM::snapshot($store);
$check(($snap['layers']['feodo']['periods']['24h']['countries']['US']['n'] ?? 0) === 3, 'snapshot from the database: US = 3 C2 servers');
$check((int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(DISTINCT bucket) FROM {$wpdb->prefix}cdtm_counts WHERE layer = %s AND grain = 'h'", 'feodo')) === 2, 'two hourly buckets stored');
$raw = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}cdtm_counts", ARRAY_N);
$check(!preg_match('/\d{1,3}(\.\d{1,3}){3}|https?:/', wp_json_encode($raw)), 'no IP or URL in the counts table');

// page HTML from the stored snapshot
$html = cyberdat_threat_map_render(cyberdat_threat_map_snapshot(), $t + 3700);
$check(str_contains($html, 'Updated 1 min ago') && str_contains($html, 'data-cdtm-cc="US"'), 'page renders the stored snapshot (status and top 10)');
// leave a clean state for the CLI checks
$store->meta_delete('state:feodo');
$store->prune('feodo', 'h', PHP_INT_MAX);
$store->prune('feodo', 'd', PHP_INT_MAX);
CDTM::rebuild_snapshot($store, time());
WP_CLI::success("threat map store on MariaDB: $n checks");
