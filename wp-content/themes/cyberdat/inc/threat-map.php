<?php
/**
 * Global Cyber Threat Map (Threat Intelligence page): server-side collector, history and page data.
 * Sources and terms: docs/THREAT-MAP-SOURCES.md. The visitor's browser loads only theme files and the counts
 * embedded in the page; it never contacts a source.
 */
defined('ABSPATH') || exit;

require_once __DIR__ . '/threat-map/core.php';
require_once __DIR__ . '/threat-map/view.php';
require_once __DIR__ . '/threat-map/render.php';
require_once __DIR__ . '/threat-map/store-wpdb.php';
require_once __DIR__ . '/threat-map/cli.php';

/** The stored snapshot, or null when the tables are not migrated yet or nothing was collected. */
function cyberdat_threat_map_snapshot(): ?array {
	try {
		return CDTM::snapshot(new CDTM_Wpdb_Store());
	} catch (Throwable $e) {
		return null;
	}
}
