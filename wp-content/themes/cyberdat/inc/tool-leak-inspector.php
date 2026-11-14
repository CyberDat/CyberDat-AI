<?php
/**
 * System Prompt & Agent Leak Inspector (Tools release 1.2, tool 5).
 *
 * Registers the reviewed renderer for the native page /tools/agent-leak-inspector/ (URL from the roadmap,
 * confirmed by the owner at acceptance). Publication still requires the editorial fields and the "reviewed"
 * flag enforced by inc/tools.php. Uses the shared tool framework: strict CSP (inc/tool-security.php), Web Worker,
 * assets/css/tools-common.css. No external data is bundled and no AI model or service is called.
 */
defined( 'ABSPATH' ) || exit;

const CYBERDAT_LKI_SLUG = 'agent-leak-inspector';
const CYBERDAT_LKI_ENGINE = '1.0.0';
const CYBERDAT_LKI_RULESET = '2026-11-14.1';

/** True only for the tool page that is a direct child of the /tools/ hub. */
function cyberdat_lki_is_page( $post_id ) {
	$post = get_post( $post_id );
	if ( ! $post || 'page' !== $post->post_type || CYBERDAT_LKI_SLUG !== $post->post_name || ! cyberdat_is_tool( $post->ID ) ) {
		return false;
	}
	$parent = $post->post_parent ? get_post( $post->post_parent ) : null;
	return $parent && 'tools' === $parent->post_name;
}

function cyberdat_lki_renderer( $renderer, $post_id ) {
	return cyberdat_lki_is_page( $post_id ) ? 'cyberdat_lki_render' : $renderer;
}
add_filter( 'cyberdat/tool/renderer', 'cyberdat_lki_renderer', 10, 2 );

function cyberdat_lki_config() {
	$worker = '/assets/js/leak-inspector/worker.js';
	$engine = '/assets/js/leak-inspector/engine.js';
	return array(
		'worker'         => add_query_arg( array( 'ver' => cyberdat_theme_asset_version( $worker ), 'ev' => cyberdat_theme_asset_version( $engine ) ), get_theme_file_uri( $worker ) ),
		'engine_version' => CYBERDAT_LKI_ENGINE,
		'ruleset'        => CYBERDAT_LKI_RULESET,
	);
}

function cyberdat_lki_render( $post_id ) {
	get_template_part( 'template-parts/tools/agent-leak-inspector' );
}

function cyberdat_lki_assets() {
	if ( ! is_singular( 'page' ) || ! cyberdat_lki_is_page( get_queried_object_id() ) ) {
		return;
	}
	wp_enqueue_style( 'cyberdat-tools-common', get_theme_file_uri( '/assets/css/tools-common.css' ), array( 'cyberdat-tools' ), cyberdat_theme_asset_version( '/assets/css/tools-common.css' ) );
	wp_enqueue_style( 'cyberdat-leak-inspector', get_theme_file_uri( '/assets/css/leak-inspector.css' ), array( 'cyberdat-tools-common' ), cyberdat_theme_asset_version( '/assets/css/leak-inspector.css' ) );
	wp_enqueue_script( 'cyberdat-leak-inspector', get_theme_file_uri( '/assets/js/leak-inspector/app.js' ), array(), cyberdat_theme_asset_version( '/assets/js/leak-inspector/app.js' ), array( 'strategy' => 'defer', 'in_footer' => true ) );
}
add_action( 'wp_enqueue_scripts', 'cyberdat_lki_assets', 20 );
