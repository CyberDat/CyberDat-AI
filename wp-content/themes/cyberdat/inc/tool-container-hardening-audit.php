<?php
/**
 * Docker & Kubernetes Hardening Audit Generator (Tools release 1.3, tool 10).
 *
 * Registers the reviewed renderer for the native page /tools/container-hardening-audit/ (URL from the catalogue entry).
 * Publication still requires the editorial fields and the "reviewed" flag enforced by inc/tools.php. Uses the shared tool
 * framework: strict CSP (inc/tool-security.php), Web Worker, assets/css/tools-common.css. Files are checked statically;
 * nothing is built, deployed, changed or sent anywhere.
 */
defined( 'ABSPATH' ) || exit;

const CYBERDAT_CHA_SLUG = 'container-hardening-audit';
const CYBERDAT_CHA_ENGINE = '1.0.0';
const CYBERDAT_CHA_RULESET = '2026-11-18.1';

/** True only for the tool page that is a direct child of the /tools/ hub. */
function cyberdat_cha_is_page( $post_id ) {
	$post = get_post( $post_id );
	if ( ! $post || 'page' !== $post->post_type || CYBERDAT_CHA_SLUG !== $post->post_name || ! cyberdat_is_tool( $post->ID ) ) {
		return false;
	}
	$parent = $post->post_parent ? get_post( $post->post_parent ) : null;
	return $parent && 'tools' === $parent->post_name;
}

function cyberdat_cha_renderer( $renderer, $post_id ) {
	return cyberdat_cha_is_page( $post_id ) ? 'cyberdat_cha_render' : $renderer;
}
add_filter( 'cyberdat/tool/renderer', 'cyberdat_cha_renderer', 10, 2 );

function cyberdat_cha_config() {
	$worker = '/assets/js/container-hardening-audit/worker.js';
	$engine = '/assets/js/container-hardening-audit/engine.js';
	return array(
		'worker'         => add_query_arg( array( 'ver' => cyberdat_theme_asset_version( $worker ), 'ev' => cyberdat_theme_asset_version( $engine ) ), get_theme_file_uri( $worker ) ),
		'engine_version' => CYBERDAT_CHA_ENGINE,
		'ruleset'        => CYBERDAT_CHA_RULESET,
	);
}

function cyberdat_cha_render( $post_id ) {
	get_template_part( 'template-parts/tools/container-hardening-audit' );
}

function cyberdat_cha_assets() {
	if ( ! is_singular( 'page' ) || ! cyberdat_cha_is_page( get_queried_object_id() ) ) {
		return;
	}
	wp_enqueue_style( 'cyberdat-tools-common', get_theme_file_uri( '/assets/css/tools-common.css' ), array( 'cyberdat-tools' ), cyberdat_theme_asset_version( '/assets/css/tools-common.css' ) );
	wp_enqueue_style( 'cyberdat-container-hardening-audit', get_theme_file_uri( '/assets/css/container-hardening-audit.css' ), array( 'cyberdat-tools-common' ), cyberdat_theme_asset_version( '/assets/css/container-hardening-audit.css' ) );
	wp_enqueue_script( 'cyberdat-container-hardening-audit', get_theme_file_uri( '/assets/js/container-hardening-audit/app.js' ), array(), cyberdat_theme_asset_version( '/assets/js/container-hardening-audit/app.js' ), array( 'strategy' => 'defer', 'in_footer' => true ) );
}
add_action( 'wp_enqueue_scripts', 'cyberdat_cha_assets', 20 );
