<?php
/** Guarded canonical Tools editorial/Rank Math integration; no unrelated pages. */
defined( 'ABSPATH' ) || exit( 1 );
require_once __DIR__ . '/staging-contract.php';
cd_tools_assert_staging();
$cd_mode = $args[0] ?? 'plan';
$cd_slugs = array( 'log-anonymizer', 'prompt-injection-detector', 'lotl-command-analyzer', 'mcp-security-checker' );
cd_tools_decisions( $cd_mode, $cd_slugs );
if ( ! in_array( $cd_mode, array( 'plan', 'draft', 'reviewed', 'publish' ), true ) ) { throw new RuntimeException( 'Unknown editorial mode' ); }
if ( ! class_exists( '\RankMath\Schema\DB' ) ) { throw new RuntimeException( 'Installed Rank Math schema module required' ); }
$cd_copy = json_decode( file_get_contents( __DIR__ . '/editorial-integration.json' ), true, 64, JSON_THROW_ON_ERROR );
if ( array_keys( $cd_copy ) !== $cd_slugs ) { throw new RuntimeException( 'Exact four-page editorial set required' ); }
$cd_hub = get_page_by_path( 'tools' );
if ( ! $cd_hub || 50 !== (int) $cd_hub->ID || 'publish' !== $cd_hub->post_status || 'page-templates/tools.php' !== get_page_template_slug( $cd_hub->ID ) ) { throw new RuntimeException( 'Hub identity conflict' ); }
$cd_pages = array();
global $wpdb;
foreach ( $cd_slugs as $slug ) {
	$rows = $wpdb->get_results( $wpdb->prepare( "SELECT ID,post_parent,post_status FROM {$wpdb->posts} WHERE post_type='page' AND post_name=%s", $slug ) );
	if ( count( $rows ) > 1 || ( $rows && (int) $rows[0]->post_parent !== 50 ) ) { throw new RuntimeException( 'Canonical page conflict' ); }
	$page = $rows ? get_post( $rows[0]->ID ) : null;
	// Only the known old Log draft may pre-exist on the first integration.
	if ( $page && ! ( 'log-anonymizer' === $slug && 51 === (int) $page->ID && 'draft' === $page->post_status ) && 'integration-1' !== get_post_meta( $page->ID, '_cyberdat_tools_editorial_revision', true ) ) { throw new RuntimeException( 'Unowned page refused' ); }
	if ( $page && 'page-templates/tool.php' !== get_page_template_slug( $page->ID ) ) { throw new RuntimeException( 'Page template conflict' ); }
	if ( $page && ! in_array( $page->post_status, array( 'draft', 'publish' ), true ) ) { throw new RuntimeException( 'Page status conflict' ); }
	if ( $page && 'draft' === $cd_mode && 'publish' === $page->post_status ) { throw new RuntimeException( 'Refuse published content overwrite' ); }
	if ( $page && 'draft' === $cd_mode && \RankMath\Schema\DB::get_schemas( $page->ID ) ) { throw new RuntimeException( 'Existing schema requires separate review' ); }
	$copy = $cd_copy[$slug];
	foreach ( array( 'title', 'summary', 'article', 'how_it_works', 'documentation', 'examples', 'faq' ) as $key ) {
		if ( empty( $copy[$key] ) || ! is_string( $copy[$key] ) ) { throw new RuntimeException( 'Missing editorial field' ); }
	}
	if ( strpos( $copy['article'], '<h1' ) !== false || strpos( $copy['article'], '[' ) !== false || wp_kses_post( $copy['article'] ) !== $copy['article'] ) { throw new RuntimeException( 'Unsafe editorial HTML/shortcode' ); }
	if ( count( $copy['questions'] ) !== 4 ) { throw new RuntimeException( 'Visible FAQ contract mismatch' ); }
	foreach ( $copy['questions'] as $qa ) {
		if ( strpos( html_entity_decode( wp_strip_all_tags( $copy['article'] ), ENT_QUOTES, 'UTF-8' ), $qa['question'] ) === false || strpos( html_entity_decode( wp_strip_all_tags( $copy['article'] ), ENT_QUOTES, 'UTF-8' ), $qa['answer'] ) === false ) { throw new RuntimeException( 'Schema FAQ not visible' ); }
	}
	$cd_pages[$slug] = $page;
}
if ( $wpdb->last_error ) { throw new RuntimeException( 'Page preflight SQL failure' ); }
if ( 'plan' === $cd_mode ) { echo wp_json_encode( array( 'plan' => array_map( static fn( $p ) => $p ? (int) $p->ID : null, $cd_pages ) ) ); return; }
$cd_changed = array();
if ( false === $wpdb->query( 'START TRANSACTION' ) ) { throw new RuntimeException( 'Cannot start editorial transaction' ); }
try {
	foreach ( $cd_slugs as $slug ) {
		cd_tools_assert_staging();
		$page = $cd_pages[$slug]; $copy = $cd_copy[$slug];
		if ( 'draft' === $cd_mode ) {
			$post = array( 'post_type' => 'page', 'post_status' => 'draft', 'post_title' => $copy['title'], 'post_name' => $slug, 'post_parent' => 50, 'post_content' => $copy['article'], 'post_excerpt' => $copy['summary'] );
			if ( $page ) { $post['ID'] = $page->ID; }
			$id = wp_insert_post( wp_slash( $post ), true );
			if ( is_wp_error( $id ) ) { throw new RuntimeException( 'Draft write failed' ); }
			$cd_changed[] = $id;
			$meta = array( 'reviewed' => false );
			foreach ( array( 'summary', 'how_it_works', 'documentation', 'examples', 'faq' ) as $key ) { $meta[$key] = $copy[$key]; }
			update_post_meta( $id, '_wp_page_template', 'page-templates/tool.php' );
			update_post_meta( $id, '_cyberdat_tool', wp_slash( cyberdat_tool_sanitize( $meta ) ) );
			update_post_meta( $id, '_cyberdat_tools_editorial_revision', 'integration-1' );
			$url = home_url( '/tools/' . $slug . '/' );
			$seo = array( 'rank_math_title' => $copy['seo']['title'], 'rank_math_description' => $copy['seo']['description'], 'rank_math_focus_keyword' => $copy['seo']['keywords'], 'rank_math_canonical_url' => $url, 'rank_math_facebook_title' => $copy['seo']['title'], 'rank_math_facebook_description' => $copy['seo']['description'], 'rank_math_twitter_use_facebook' => 'on', 'rank_math_robots' => array( 'noindex', 'nofollow' ), 'rank_math_rich_snippet' => 'off' );
			foreach ( $seo as $key => $value ) { update_post_meta( $id, $key, wp_slash( $value ) ); }
			$software = array( '@type' => 'SoftwareApplication', '@id' => $url . '#software', 'name' => $copy['title'], 'url' => $url, 'description' => $copy['summary'], 'applicationCategory' => 'SecurityApplication', 'operatingSystem' => 'Web browser', 'browserRequirements' => 'JavaScript and Web Workers enabled', 'inLanguage' => 'en', 'metadata' => array( 'title' => 'SoftwareApplication', 'type' => 'template', 'isPrimary' => true ) );
			$faq = array( '@type' => 'FAQPage', '@id' => $url . '#faq', 'mainEntity' => array(), 'metadata' => array( 'title' => 'FAQPage', 'type' => 'template', 'isPrimary' => false ) );
			foreach ( $copy['questions'] as $qa ) { $faq['mainEntity'][] = array( '@type' => 'Question', 'name' => $qa['question'], 'acceptedAnswer' => array( '@type' => 'Answer', 'text' => $qa['answer'] ) ); }
			update_post_meta( $id, 'rank_math_schema_SoftwareApplication', wp_slash( $software ) );
			update_post_meta( $id, 'rank_math_schema_FAQPage', wp_slash( $faq ) );
		} else {
			if ( ! $page ) { throw new RuntimeException( 'Draft required first' ); }
			$id = $page->ID; $cd_changed[] = $id;
			if ( get_post_field( 'post_content', $id ) !== $copy['article'] ) { throw new RuntimeException( 'Editorial content drift' ); }
			if ( 'reviewed' === $cd_mode ) {
				$meta = cyberdat_tool_data( $id ); $meta['reviewed'] = true; update_post_meta( $id, '_cyberdat_tool', wp_slash( $meta ) );
			} else {
				if ( ! cyberdat_tool_ready( $id ) ) { throw new RuntimeException( 'Readiness required' ); }
				$r = wp_update_post( array( 'ID' => $id, 'post_status' => 'publish' ), true );
				if ( is_wp_error( $r ) || 'publish' !== get_post_status( $id ) ) { throw new RuntimeException( 'Publication failed' ); }
			}
		}
		if ( $wpdb->last_error ) { throw new RuntimeException( 'Editorial SQL failure' ); }
	}
	if ( false === $wpdb->query( 'COMMIT' ) ) { throw new RuntimeException( 'Editorial commit failed' ); }
} catch ( Throwable $e ) {
	$wpdb->query( 'ROLLBACK' );
	foreach ( $cd_changed as $id ) { clean_post_cache( $id ); wp_cache_delete( $id, 'post_meta' ); }
	throw $e;
}
echo wp_json_encode( array( 'mode' => $cd_mode, 'pages' => array_values( $cd_changed ), 'scope' => 'four canonical tools only' ) );
