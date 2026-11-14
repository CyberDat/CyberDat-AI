<?php
/** Private selective page/meta snapshot and restore. Never loads a SQL dump. */
require_once __DIR__ . '/staging-contract.php';
cd_tools_assert_staging();
function cd_tools_slugs() {
	return array( 'log-anonymizer', 'prompt-injection-detector', 'lotl-command-analyzer', 'mcp-security-checker' );
}
$cd_slugs = cd_tools_slugs();

function cd_tools_snapshot( $locking = false ) {
	global $wpdb;
	$cd_slugs = cd_tools_slugs();
	$hub = $wpdb->get_row( "SELECT * FROM {$wpdb->posts} WHERE post_type='page' AND post_name='tools' AND post_parent=0" . ( $locking ? ' FOR UPDATE' : '' ), ARRAY_A );
	if ( ! $hub || 'publish' !== $hub['post_status'] ) { throw new RuntimeException( 'Tools hub unavailable' ); }
	$out = array( 'hub_id' => $hub['ID'], 'pages' => array() );
	foreach ( $cd_slugs as $slug ) {
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->posts} WHERE post_type='page' AND post_name=%s AND post_parent=%d" . ( $locking ? ' FOR UPDATE' : '' ), $slug, $hub['ID'] ), ARRAY_A );
		if ( count( $rows ) > 1 ) { throw new RuntimeException( 'Duplicate tool slug' ); }
		$records = array();
		if ( $rows ) {
			$page = $rows[0];
			$revisions = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->posts} WHERE post_type='revision' AND post_parent=%d ORDER BY ID" . ( $locking ? ' FOR UPDATE' : '' ), $page['ID'] ), ARRAY_A );
			foreach ( array_merge( array( $page ), $revisions ) as $row ) {
				$meta = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->postmeta} WHERE post_id=%d ORDER BY meta_id" . ( $locking ? ' FOR UPDATE' : '' ), $row['ID'] ), ARRAY_A );
				$records[] = array( 'post' => $row, 'meta' => $meta );
			}
		}
		$out['pages'][$slug] = $records;
	}
	if ( $wpdb->last_error ) { throw new RuntimeException( 'Selective page snapshot SQL failure' ); }
	return $out;
}

function cd_tools_restore( $before, $expected ) {
	global $wpdb;
	$cd_slugs = cd_tools_slugs();
	cd_tools_assert_staging();
	$old_suppression = $wpdb->suppress_errors( true );
	$changed = array();
	try {
		$engines = $wpdb->get_col( $wpdb->prepare( 'SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s AND TABLE_NAME IN (%s,%s)', DB_NAME, $wpdb->posts, $wpdb->postmeta ) );
		if ( count( $engines ) !== 2 || array_filter( $engines, static fn( $engine ) => 'InnoDB' !== $engine ) ) { throw new RuntimeException( 'Selective restore requires InnoDB' ); }
		if ( false === $wpdb->query( 'START TRANSACTION' ) ) { throw new RuntimeException( 'Cannot start selective restore transaction' ); }
		$current = cd_tools_snapshot( true );
		if ( $current === $before ) { $wpdb->query( 'ROLLBACK' ); return; }
		if ( $current !== $expected || $current['hub_id'] !== $before['hub_id'] || array_keys( $before['pages'] ) !== $cd_slugs ) {
			throw new RuntimeException( 'Unknown page/meta changes: selective rollback refused' );
		}
		foreach ( $cd_slugs as $slug ) {
			foreach ( $current['pages'][$slug] as $record ) {
				$id = (int) $record['post']['ID']; $changed[] = $id;
				if ( false === $wpdb->delete( $wpdb->postmeta, array( 'post_id' => $id ) ) || false === $wpdb->delete( $wpdb->posts, array( 'ID' => $id ) ) ) { throw new RuntimeException( 'Selective delete failed' ); }
			}
			foreach ( $before['pages'][$slug] as $record ) {
				$id = (int) $record['post']['ID']; $changed[] = $id;
				if ( false === $wpdb->insert( $wpdb->posts, $record['post'] ) ) { throw new RuntimeException( 'Selective page restore conflict' ); }
				foreach ( $record['meta'] as $meta ) {
					if ( false === $wpdb->insert( $wpdb->postmeta, $meta ) ) { throw new RuntimeException( 'Selective metadata restore conflict' ); }
				}
			}
		}
		if ( cd_tools_snapshot( true ) !== $before ) { throw new RuntimeException( 'Selective restore differs from snapshot' ); }
		if ( false === $wpdb->query( 'COMMIT' ) ) { throw new RuntimeException( 'Selective commit failed' ); }
	} catch ( Throwable $e ) {
		$wpdb->query( 'ROLLBACK' ); throw $e;
	} finally { $wpdb->suppress_errors( $old_suppression ); }
	foreach ( array_unique( $changed ) as $id ) { clean_post_cache( $id ); wp_cache_delete( $id, 'post_meta' ); }
	wp_cache_set_posts_last_changed();
}

$mode = $args[0] ?? 'snapshot';
if ( in_array( $mode, array( 'plan', 'draft', 'reviewed', 'publish' ), true ) ) { require __DIR__ . '/tool-pages.php'; return; }
if ( 'snapshot' === $mode ) { echo wp_json_encode( cd_tools_snapshot(), JSON_THROW_ON_ERROR ); }
elseif ( 'restore' === $mode ) {
	$raw = stream_get_contents( STDIN, 2097153 );
	if ( strlen( $raw ) > 2097152 ) { throw new RuntimeException( 'Snapshot payload too large' ); }
	$d = json_decode( $raw, true, 64, JSON_THROW_ON_ERROR );
	cd_tools_restore( $d['before'], $d['expected'] ); echo '{"restored":true}';
} elseif ( 'routes' === $mode ) {
	$out = array();
	foreach ( $cd_slugs as $slug ) {
		$p = get_page_by_path( 'tools/' . $slug );
		$out[$slug] = array( 'published' => $p && 'publish' === $p->post_status,
			'ready' => $p && cyberdat_tool_ready( $p->ID ),
			'renderer' => $p ? cyberdat_tool_renderer( $p->ID ) : null );
	}
	echo wp_json_encode( $out );
} else { throw new RuntimeException( 'Unknown private state operation' ); }
