<?php
/**
 * YARA/Sigma Rule Validator & Converter (Tools release 1.3, tool 9).
 *
 * Registers the reviewed renderer for the native page /tools/yara-sigma-validator/ (URL from the catalogue entry).
 * Publication still requires the editorial fields and the "reviewed" flag enforced by inc/tools.php. Uses the shared tool
 * framework: strict CSP (inc/tool-security.php), Web Worker, assets/css/tools-common.css. Rules are checked statically;
 * nothing is compiled, executed or sent anywhere.
 */
defined( 'ABSPATH' ) || exit;

const CYBERDAT_YSV_SLUG = 'yara-sigma-validator';
const CYBERDAT_YSV_ENGINE = '1.0.1';
const CYBERDAT_YSV_RULESET = '2026-11-21.1';

/** True only for the tool page that is a direct child of the /tools/ hub. */
function cyberdat_ysv_is_page( $post_id ) {
	$post = get_post( $post_id );
	if ( ! $post || 'page' !== $post->post_type || CYBERDAT_YSV_SLUG !== $post->post_name || ! cyberdat_is_tool( $post->ID ) ) {
		return false;
	}
	$parent = $post->post_parent ? get_post( $post->post_parent ) : null;
	return $parent && 'tools' === $parent->post_name;
}

function cyberdat_ysv_renderer( $renderer, $post_id ) {
	return cyberdat_ysv_is_page( $post_id ) ? 'cyberdat_ysv_render' : $renderer;
}
add_filter( 'cyberdat/tool/renderer', 'cyberdat_ysv_renderer', 10, 2 );

function cyberdat_ysv_config() {
	$worker = '/assets/js/yara-sigma-validator/worker.js';
	$engine = '/assets/js/yara-sigma-validator/engine.js';
	return array(
		'worker'         => add_query_arg( array( 'ver' => cyberdat_theme_asset_version( $worker ), 'ev' => cyberdat_theme_asset_version( $engine ) ), get_theme_file_uri( $worker ) ),
		'engine_version' => CYBERDAT_YSV_ENGINE,
		'ruleset'        => CYBERDAT_YSV_RULESET,
	);
}

function cyberdat_ysv_render( $post_id ) {
	get_template_part( 'template-parts/tools/yara-sigma-validator' );
}

function cyberdat_ysv_assets() {
	if ( ! is_singular( 'page' ) || ! cyberdat_ysv_is_page( get_queried_object_id() ) ) {
		return;
	}
	wp_enqueue_style( 'cyberdat-tools-common', get_theme_file_uri( '/assets/css/tools-common.css' ), array( 'cyberdat-tools' ), cyberdat_theme_asset_version( '/assets/css/tools-common.css' ) );
	wp_enqueue_style( 'cyberdat-yara-sigma-validator', get_theme_file_uri( '/assets/css/yara-sigma-validator.css' ), array( 'cyberdat-tools-common' ), cyberdat_theme_asset_version( '/assets/css/yara-sigma-validator.css' ) );
	wp_enqueue_script( 'cyberdat-yara-sigma-validator', get_theme_file_uri( '/assets/js/yara-sigma-validator/app.js' ), array(), cyberdat_theme_asset_version( '/assets/js/yara-sigma-validator/app.js' ), array( 'strategy' => 'defer', 'in_footer' => true ) );
}
add_action( 'wp_enqueue_scripts', 'cyberdat_ysv_assets', 20 );
