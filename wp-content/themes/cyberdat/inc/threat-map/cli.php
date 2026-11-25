<?php
/**
 * WP-CLI: wp cyberdat threatmap migrate | sync [--layer=<id>] [--force] | status | uninstall --yes
 * Started by a systemd timer on the server (samples in docs/threat-map/); WP-Cron is not used.
 */
defined('ABSPATH') || exit;

if (defined('WP_CLI') && WP_CLI && class_exists('WP_CLI')) {

	/** CyberDat site commands. */
	if (class_exists('WP_CLI\Dispatcher\CommandNamespace')) {
		final class CDTM_CLI_Namespace extends \WP_CLI\Dispatcher\CommandNamespace {}
	}

	/**
	 * Global Cyber Threat Map collector.
	 */
	final class CDTM_CLI {
		private function store(): CDTM_Wpdb_Store {
			$store = new CDTM_Wpdb_Store();
			if (!$store->installed()) WP_CLI::error('Threat map tables are missing. Run: wp cyberdat threatmap migrate');
			return $store;
		}

		/**
		 * Creates or updates the tables {prefix}cdtm_counts and {prefix}cdtm_meta.
		 */
		public function migrate($args, $assoc) {
			$store = new CDTM_Wpdb_Store();
			try { $store->install(); } catch (Throwable $e) { WP_CLI::error($e->getMessage()); }
			CDTM::rebuild_snapshot($store, time());
			WP_CLI::success('Tables ready: ' . implode(', ', $store->tables()));
		}

		/**
		 * Collects the layers that are due (each once an hour, in its own minute slot).
		 *
		 * [--layer=<id>]
		 * : Only this layer (feodo, ransomware).
		 *
		 * [--force]
		 * : Run outside the slot. The source's MIN_INTERVAL still applies.
		 */
		public function sync($args, $assoc) {
			$store = $this->store();
			$ids = array_keys(CDTM::layers());
			if (isset($assoc['layer'])) {
				if (!in_array($assoc['layer'], $ids, true)) WP_CLI::error('Unknown layer. Known: ' . implode(', ', $ids));
				$ids = [$assoc['layer']];
			}
			$failed = 0;
			foreach ($ids as $id) {
				$r = CDTM::sync_layer($store, 'cdtm_http', $id, time(), !empty($assoc['force']));
				$line = sprintf('%s: %s — %s', $id, $r['result'], $r['message']);
				if ($r['result'] === 'error') { $failed++; WP_CLI::warning($line); } else WP_CLI::log($line);
			}
			if ($failed) WP_CLI::halt(1);
		}

		/**
		 * Shows per layer: last success, status, last error, history size.
		 *
		 * [--format=<format>]
		 * : table (default), json or csv.
		 */
		public function status($args, $assoc) {
			$rows = CDTM::status_rows($this->store(), time());
			\WP_CLI\Utils\format_items($assoc['format'] ?? 'table', $rows, array_keys($rows[0]));
		}

		/**
		 * Rollback: drops both threat map tables (counters, history, state and snapshot).
		 *
		 * [--yes]
		 * : Confirm dropping the tables.
		 */
		public function uninstall($args, $assoc) {
			if (empty($assoc['yes'])) WP_CLI::error('Add --yes to drop the threat map tables.');
			(new CDTM_Wpdb_Store())->uninstall();
			WP_CLI::success('Threat map tables dropped.');
		}
	}

	if (class_exists('CDTM_CLI_Namespace')) WP_CLI::add_command('cyberdat', 'CDTM_CLI_Namespace');
	WP_CLI::add_command('cyberdat threatmap', 'CDTM_CLI');
}
