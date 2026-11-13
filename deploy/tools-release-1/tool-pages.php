<?php
/**
 * Staging tool pages for release 1 — run with WP-CLI as the staging runtime user:
 *
 *   wp --path=/var/www/cyberdat-staging/public eval-file tool-pages.php <mode> <deploy-dir> [slug,slug]
 *
 * <deploy-dir> is the repository "deploy" directory of the exported integration commit (contains tools-*\/editorial.json).
 * Modes (each one is a separate owner-approved step):
 *   plan      read-only (default): shows the existing page per slug and what "draft" would change.
 *   draft     creates the page as a draft under /tools/ (or updates a draft) with the Tool template and the
 *             editorial fields; reviewed stays false. Published pages are never changed by this mode.
 *   reviewed  sets reviewed=true — only after the owner has read the page texts (COPY-REVIEW.md).
 *   publish   publishes pages that are reviewed and pass cyberdat_tool_ready().
 * Fails closed on an unexpected parent, template or page type. Rank Math fields are reported, never changed.
 */
defined( 'ABSPATH' ) || exit( 1 );
require_once __DIR__ . '/staging-contract.php';
cd_tools_assert_staging();

$cd_args  = isset( $args ) && is_array( $args ) ? $args : array();
$cd_mode  = $cd_args[0] ?? 'plan';
$cd_dir   = rtrim( (string) ( $cd_args[1] ?? '' ), '/\\' );
$cd_tools = array(
	'log-anonymizer'            => 'tools-log-anonymizer',
	'prompt-injection-detector' => 'tools-prompt-injection-detector',
	'lotl-command-analyzer'     => 'tools-lotl-analyzer',
	'mcp-security-checker'      => 'tools-mcp-checker',
);
$cd_only = isset( $cd_args[2] ) ? array_filter( explode( ',', $cd_args[2] ) ) : array_keys( $cd_tools );
cd_tools_decisions( $cd_mode, $cd_only );

function cd_fail( $message ) {
	fwrite( STDERR, 'FAIL: ' . $message . PHP_EOL );
	exit( 1 );
}
if ( ! in_array( $cd_mode, array( 'plan', 'draft', 'reviewed', 'publish' ), true ) ) { cd_fail( 'unknown mode ' . $cd_mode ); }
if ( ! is_dir( $cd_dir ) ) { cd_fail( 'deploy directory not found: ' . $cd_dir ); }
foreach ( array( 'cyberdat_tool_sanitize', 'cyberdat_tool_ready', 'cyberdat_is_tool' ) as $fn ) {
	if ( ! function_exists( $fn ) ) { cd_fail( 'the CyberDat theme with ' . $fn . '() is not active' ); }
}
$cd_hub = get_page_by_path( 'tools' );
if ( ! $cd_hub || 'page' !== $cd_hub->post_type || 'publish' !== $cd_hub->post_status ) { cd_fail( 'published /tools/ hub page not found' ); }

foreach ( $cd_only as $slug ) {
	if ( ! isset( $cd_tools[ $slug ] ) ) { cd_fail( 'unknown slug ' . $slug ); }
	$copy = json_decode( (string) file_get_contents( $cd_dir . '/' . $cd_tools[ $slug ] . '/editorial.json' ), true );
	if ( ! is_array( $copy ) || empty( $copy['title'] ) ) { cd_fail( $slug . ': editorial.json missing or invalid' ); }
	$page = get_page_by_path( 'tools/' . $slug );
	$line = $slug . ': ';
	if ( $page ) {
		if ( 'page' !== $page->post_type || (int) $page->post_parent !== (int) $cd_hub->ID ) { cd_fail( $slug . ': existing post is not a child page of /tools/' ); }
		$tpl  = get_page_template_slug( $page->ID );
		$meta = cyberdat_tool_sanitize( get_post_meta( $page->ID, '_cyberdat_tool', true ) );
		$line .= sprintf( 'existing ID %d, status %s, template %s, reviewed %s, ready %s, architecture %s, rank_math_description "%s"', $page->ID, $page->post_status, $tpl ? $tpl : '(default)', $meta['reviewed'] ? 'yes' : 'no', cyberdat_tool_ready( $page->ID ) ? 'yes' : 'no', (string) get_post_meta( $page->ID, '_cyberdat_tools_architecture', true ), mb_substr( (string) get_post_meta( $page->ID, 'rank_math_description', true ), 0, 80 ) );
		if ( $tpl && 'page-templates/tool.php' !== $tpl ) { cd_fail( $slug . ': unexpected template ' . $tpl ); }
	} else {
		$line .= 'no page yet';
	}
	if ( 'plan' === $cd_mode ) {
		echo $line . ' → draft would ' . ( $page ? ( 'publish' === $page->post_status ? 'NOT change it (already published)' : 'update fields, keep reviewed=false' ) : 'create a draft' ) . PHP_EOL;
		continue;
	}
	if ( 'draft' === $cd_mode ) {
		if ( $page && ! in_array( $page->post_status, array( 'draft', 'publish' ), true ) ) { cd_fail( $slug . ': unexpected editorial status; do not overwrite' ); }
		if ( $page && 'publish' === $page->post_status ) { echo $line . ' → skipped (published pages are not changed by draft)' . PHP_EOL; continue; }
		$meta = array( 'reviewed' => false );
		foreach ( array( 'summary', 'how_it_works', 'documentation', 'examples', 'faq' ) as $key ) { $meta[ $key ] = (string) ( $copy[ $key ] ?? '' ); }
		$id = $page ? $page->ID : wp_insert_post( array( 'post_type' => 'page', 'post_status' => 'draft', 'post_title' => $copy['title'], 'post_name' => $slug, 'post_parent' => $cd_hub->ID, 'post_content' => '' ), true );
		if ( is_wp_error( $id ) ) { cd_fail( $slug . ': ' . $id->get_error_message() ); }
		update_post_meta( $id, '_wp_page_template', 'page-templates/tool.php' );
		update_post_meta( $id, '_cyberdat_tool', cyberdat_tool_sanitize( $meta ) );
		wp_update_post( array( 'ID' => $id, 'post_title' => $copy['title'], 'post_status' => 'draft' ) );
		echo $line . ' → draft ID ' . $id . ' with editorial fields, reviewed=false' . PHP_EOL;
		continue;
	}
	if ( ! $page ) { cd_fail( $slug . ': run "draft" first' ); }
	if ( 'reviewed' === $cd_mode ) {
		$meta = cyberdat_tool_sanitize( get_post_meta( $page->ID, '_cyberdat_tool', true ) );
		$meta['reviewed'] = true;
		update_post_meta( $page->ID, '_cyberdat_tool', cyberdat_tool_sanitize( $meta ) );
		echo $line . ' → reviewed=true, ready ' . ( cyberdat_tool_ready( $page->ID ) ? 'yes' : 'NO' ) . PHP_EOL;
		continue;
	}
	if ( ! cyberdat_tool_ready( $page->ID ) ) { cd_fail( $slug . ': not ready (reviewed, fields, template and renderer are all required); not published' ); }
	wp_update_post( array( 'ID' => $page->ID, 'post_status' => 'publish' ) );
	echo $line . ' → published at ' . get_permalink( $page->ID ) . PHP_EOL;
}
