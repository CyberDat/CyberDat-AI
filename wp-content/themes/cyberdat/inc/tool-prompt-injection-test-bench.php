<?php
/**
 * LLM Prompt Injection Test Bench (Tools release 1.3, tool 8).
 *
 * Registers the reviewed renderer for the native page /tools/prompt-injection-test-bench/ (URL from the catalogue entry).
 * Publication still requires the editorial fields and the "reviewed" flag enforced by inc/tools.php. Uses the shared tool
 * framework: strict CSP (inc/tool-security.php), Web Worker, assets/css/tools-common.css. The test library is fixed and
 * written by CyberDat; the tool sends nothing to any application, model or service.
 */
defined( 'ABSPATH' ) || exit;

const CYBERDAT_PITB_SLUG = 'prompt-injection-test-bench';
const CYBERDAT_PITB_ENGINE = '1.0.1';
const CYBERDAT_PITB_LIBRARY = '2026-11-21.1';

/** Application types offered in step 1 (keys and labels equal engine.js APP_TYPES; checked by tests). */
function cyberdat_pitb_app_types() {
	return array(
		'chat'  => __( 'Chat assistant', 'cyberdat' ),
		'rag'   => __( 'Retrieval (RAG) over documents', 'cyberdat' ),
		'agent' => __( 'Agent with tools', 'cyberdat' ),
		'docs'  => __( 'Email or document processing', 'cyberdat' ),
	);
}

/** True only for the tool page that is a direct child of the /tools/ hub. */
function cyberdat_pitb_is_page( $post_id ) {
	$post = get_post( $post_id );
	if ( ! $post || 'page' !== $post->post_type || CYBERDAT_PITB_SLUG !== $post->post_name || ! cyberdat_is_tool( $post->ID ) ) {
		return false;
	}
	$parent = $post->post_parent ? get_post( $post->post_parent ) : null;
	return $parent && 'tools' === $parent->post_name;
}

function cyberdat_pitb_renderer( $renderer, $post_id ) {
	return cyberdat_pitb_is_page( $post_id ) ? 'cyberdat_pitb_render' : $renderer;
}
add_filter( 'cyberdat/tool/renderer', 'cyberdat_pitb_renderer', 10, 2 );

function cyberdat_pitb_config() {
	$worker = '/assets/js/prompt-injection-test-bench/worker.js';
	$engine = '/assets/js/prompt-injection-test-bench/engine.js';
	return array(
		'worker'         => add_query_arg( array( 'ver' => cyberdat_theme_asset_version( $worker ), 'ev' => cyberdat_theme_asset_version( $engine ) ), get_theme_file_uri( $worker ) ),
		'engine_version' => CYBERDAT_PITB_ENGINE,
		'library'        => CYBERDAT_PITB_LIBRARY,
	);
}

function cyberdat_pitb_render( $post_id ) {
	get_template_part( 'template-parts/tools/prompt-injection-test-bench' );
}

function cyberdat_pitb_assets() {
	if ( ! is_singular( 'page' ) || ! cyberdat_pitb_is_page( get_queried_object_id() ) ) {
		return;
	}
	wp_enqueue_style( 'cyberdat-tools-common', get_theme_file_uri( '/assets/css/tools-common.css' ), array( 'cyberdat-tools' ), cyberdat_theme_asset_version( '/assets/css/tools-common.css' ) );
	wp_enqueue_style( 'cyberdat-prompt-injection-test-bench', get_theme_file_uri( '/assets/css/prompt-injection-test-bench.css' ), array( 'cyberdat-tools-common' ), cyberdat_theme_asset_version( '/assets/css/prompt-injection-test-bench.css' ) );
	wp_enqueue_script( 'cyberdat-prompt-injection-test-bench', get_theme_file_uri( '/assets/js/prompt-injection-test-bench/app.js' ), array(), cyberdat_theme_asset_version( '/assets/js/prompt-injection-test-bench/app.js' ), array( 'strategy' => 'defer', 'in_footer' => true ) );
}
add_action( 'wp_enqueue_scripts', 'cyberdat_pitb_assets', 20 );
