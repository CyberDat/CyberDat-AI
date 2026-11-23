<?php
/**
 * Email Header Analyzer (quick utilities, utility 1).
 *
 * Registers the reviewed renderer for the native page /tools/email-header-analyzer/ (URL confirmed by the owner on
 * 2026-11-19). Publication still requires the editorial fields and the "reviewed" flag enforced by
 * inc/tools.php. Uses the shared tool framework: strict CSP (inc/tool-security.php), Web Worker,
 * assets/css/tools-common.css. Headers are analysed in the browser; nothing is looked up or sent anywhere.
 */
defined( 'ABSPATH' ) || exit;

const CYBERDAT_EHA_SLUG = 'email-header-analyzer';
const CYBERDAT_EHA_ENGINE = '1.0.0';
const CYBERDAT_EHA_RULESET = '2026-11-23.1';
const CYBERDAT_EHA_PSL_DATE = '2026-11-17';
const CYBERDAT_EHA_PSL_SHA256 = '809adae1a2cb1621b70165c11e0d14412d3f104f40a4ebed9a99e23c54f78d71';

/** True only for the tool page that is a direct child of the /tools/ hub. */
function cyberdat_eha_is_page( $post_id ) {
	$post = get_post( $post_id );
	if ( ! $post || 'page' !== $post->post_type || CYBERDAT_EHA_SLUG !== $post->post_name || ! cyberdat_is_tool( $post->ID ) ) {
		return false;
	}
	$parent = $post->post_parent ? get_post( $post->post_parent ) : null;
	return $parent && 'tools' === $parent->post_name;
}

function cyberdat_eha_renderer( $renderer, $post_id ) {
	return cyberdat_eha_is_page( $post_id ) ? 'cyberdat_eha_render' : $renderer;
}
add_filter( 'cyberdat/tool/renderer', 'cyberdat_eha_renderer', 10, 2 );

function cyberdat_eha_config() {
	$worker = '/assets/js/email-header-analyzer/worker.js';
	$engine = '/assets/js/email-header-analyzer/engine.js';
	$psl    = '/assets/js/email-header-analyzer/psl-data.js';
	return array(
		'worker'         => add_query_arg( array( 'ver' => cyberdat_theme_asset_version( $worker ), 'ev' => cyberdat_theme_asset_version( $engine ), 'pv' => cyberdat_theme_asset_version( $psl ) ), get_theme_file_uri( $worker ) ),
		'engine_version' => CYBERDAT_EHA_ENGINE,
		'ruleset'        => CYBERDAT_EHA_RULESET,
		'psl_sha256'     => CYBERDAT_EHA_PSL_SHA256,
		'psl_date'       => CYBERDAT_EHA_PSL_DATE,
	);
}

function cyberdat_eha_render( $post_id ) {
	get_template_part( 'template-parts/tools/email-header-analyzer' );
}

function cyberdat_eha_assets() {
	if ( ! is_singular( 'page' ) || ! cyberdat_eha_is_page( get_queried_object_id() ) ) {
		return;
	}
	wp_enqueue_style( 'cyberdat-tools-common', get_theme_file_uri( '/assets/css/tools-common.css' ), array( 'cyberdat-tools' ), cyberdat_theme_asset_version( '/assets/css/tools-common.css' ) );
	wp_enqueue_style( 'cyberdat-email-header-analyzer', get_theme_file_uri( '/assets/css/email-header-analyzer.css' ), array( 'cyberdat-tools-common' ), cyberdat_theme_asset_version( '/assets/css/email-header-analyzer.css' ) );
	wp_enqueue_script( 'cyberdat-email-header-analyzer', get_theme_file_uri( '/assets/js/email-header-analyzer/app.js' ), array(), cyberdat_theme_asset_version( '/assets/js/email-header-analyzer/app.js' ), array( 'strategy' => 'defer', 'in_footer' => true ) );
}
add_action( 'wp_enqueue_scripts', 'cyberdat_eha_assets', 20 );
