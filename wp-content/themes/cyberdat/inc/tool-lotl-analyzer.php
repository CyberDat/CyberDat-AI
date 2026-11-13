<?php
/**
 * LotL / LOLBAS Command Analyzer (Tools release 1.1, tool 3).
 *
 * Registers the reviewed renderer for the native page /tools/lotl-command-analyzer/
 * (proposed URL, confirmed by the owner at acceptance). Publication still requires the
 * editorial fields and the "reviewed" flag enforced by inc/tools.php. Uses the shared tool
 * framework: strict CSP (inc/tool-security.php), Web Worker, assets/css/tools-common.css.
 *
 * Windows data: build-time snapshot of the LOLBAS Project (GPL-3.0) in
 * assets/js/lotl-analyzer/lolbas-data.js; the browser never contacts GitHub.
 */
defined( 'ABSPATH' ) || exit;

const CYBERDAT_LOTL_SLUG = 'lotl-command-analyzer';
const CYBERDAT_LOTL_ENGINE = '1.0.0';
const CYBERDAT_LOTL_RULESET = '2026-11-13.1';

/** True only for the tool page that is a direct child of the /tools/ hub. */
function cyberdat_lotl_is_page( $post_id ) {
	$post = get_post( $post_id );
	if ( ! $post || 'page' !== $post->post_type || CYBERDAT_LOTL_SLUG !== $post->post_name || ! cyberdat_is_tool( $post->ID ) ) {
		return false;
	}
	$parent = $post->post_parent ? get_post( $post->post_parent ) : null;
	return $parent && 'tools' === $parent->post_name;
}

function cyberdat_lotl_renderer( $renderer, $post_id ) {
	return cyberdat_lotl_is_page( $post_id ) ? 'cyberdat_lotl_render' : $renderer;
}
add_filter( 'cyberdat/tool/renderer', 'cyberdat_lotl_renderer', 10, 2 );

/** Source commit and date of the bundled LOLBAS snapshot, read from the generated file header. */
function cyberdat_lotl_data_version() {
	static $version = null;
	if ( null === $version ) {
		$version = array( 'commit' => '', 'date' => '' );
		$head    = (string) file_get_contents( get_theme_file_path( '/assets/js/lotl-analyzer/lolbas-data.js' ), false, null, 0, 2048 );
		if ( preg_match( '/commit ([0-9a-f]{40}) \((\d{4}-\d{2}-\d{2})T/', $head, $m ) ) {
			$version = array( 'commit' => $m[1], 'date' => $m[2] );
		}
	}
	return $version;
}

function cyberdat_lotl_config() {
	$worker = '/assets/js/lotl-analyzer/worker.js';
	$engine = '/assets/js/lotl-analyzer/engine.js';
	$data   = '/assets/js/lotl-analyzer/lolbas-data.js';
	return array(
		'worker'         => add_query_arg( array( 'ver' => cyberdat_theme_asset_version( $worker ), 'ev' => cyberdat_theme_asset_version( $engine ), 'dv' => cyberdat_theme_asset_version( $data ) ), get_theme_file_uri( $worker ) ),
		'license_url'    => get_theme_file_uri( '/assets/js/lotl-analyzer/LICENSE-LOLBAS.txt' ),
		'engine_version' => CYBERDAT_LOTL_ENGINE,
		'ruleset'        => CYBERDAT_LOTL_RULESET,
		'data'           => cyberdat_lotl_data_version(),
	);
}

function cyberdat_lotl_render( $post_id ) {
	get_template_part( 'template-parts/tools/lotl-command-analyzer' );
}

function cyberdat_lotl_assets() {
	if ( ! is_singular( 'page' ) || ! cyberdat_lotl_is_page( get_queried_object_id() ) ) {
		return;
	}
	wp_enqueue_style( 'cyberdat-tools-common', get_theme_file_uri( '/assets/css/tools-common.css' ), array( 'cyberdat-tools' ), cyberdat_theme_asset_version( '/assets/css/tools-common.css' ) );
	wp_enqueue_style( 'cyberdat-lotl-analyzer', get_theme_file_uri( '/assets/css/lotl-analyzer.css' ), array( 'cyberdat-tools-common' ), cyberdat_theme_asset_version( '/assets/css/lotl-analyzer.css' ) );
	wp_enqueue_script( 'cyberdat-lotl-analyzer', get_theme_file_uri( '/assets/js/lotl-analyzer/app.js' ), array(), cyberdat_theme_asset_version( '/assets/js/lotl-analyzer/app.js' ), array( 'strategy' => 'defer', 'in_footer' => true ) );
}
add_action( 'wp_enqueue_scripts', 'cyberdat_lotl_assets', 20 );
