<?php
/**
 * AI Model Bill of Materials (Tools release 1.2, tool 6).
 *
 * Registers the reviewed renderer for the native page /tools/ai-model-bom/ (URL from the catalogue entry).
 * Publication still requires the editorial fields and the "reviewed" flag enforced by inc/tools.php. Uses the
 * shared tool framework: strict CSP (inc/tool-security.php), Web Worker, assets/css/tools-common.css.
 * No external data or schema is bundled and no model registry or other service is called.
 */
defined( 'ABSPATH' ) || exit;

const CYBERDAT_BOM_SLUG = 'ai-model-bom';
const CYBERDAT_BOM_ENGINE = '1.0.0';
const CYBERDAT_BOM_RULESET = '2026-11-14.1';
const CYBERDAT_BOM_SPEC_VERSION = '1.7';

/** True only for the tool page that is a direct child of the /tools/ hub. */
function cyberdat_bom_is_page( $post_id ) {
	$post = get_post( $post_id );
	if ( ! $post || 'page' !== $post->post_type || CYBERDAT_BOM_SLUG !== $post->post_name || ! cyberdat_is_tool( $post->ID ) ) {
		return false;
	}
	$parent = $post->post_parent ? get_post( $post->post_parent ) : null;
	return $parent && 'tools' === $parent->post_name;
}

function cyberdat_bom_renderer( $renderer, $post_id ) {
	return cyberdat_bom_is_page( $post_id ) ? 'cyberdat_bom_render' : $renderer;
}
add_filter( 'cyberdat/tool/renderer', 'cyberdat_bom_renderer', 10, 2 );

function cyberdat_bom_config() {
	$worker = '/assets/js/ai-model-bom/worker.js';
	$engine = '/assets/js/ai-model-bom/engine.js';
	return array(
		'worker'         => add_query_arg( array( 'ver' => cyberdat_theme_asset_version( $worker ), 'ev' => cyberdat_theme_asset_version( $engine ) ), get_theme_file_uri( $worker ) ),
		'engine_version' => CYBERDAT_BOM_ENGINE,
		'ruleset'        => CYBERDAT_BOM_RULESET,
		'spec_version'   => CYBERDAT_BOM_SPEC_VERSION,
	);
}

function cyberdat_bom_render( $post_id ) {
	get_template_part( 'template-parts/tools/ai-model-bom' );
}

function cyberdat_bom_assets() {
	if ( ! is_singular( 'page' ) || ! cyberdat_bom_is_page( get_queried_object_id() ) ) {
		return;
	}
	wp_enqueue_style( 'cyberdat-tools-common', get_theme_file_uri( '/assets/css/tools-common.css' ), array( 'cyberdat-tools' ), cyberdat_theme_asset_version( '/assets/css/tools-common.css' ) );
	wp_enqueue_style( 'cyberdat-ai-model-bom', get_theme_file_uri( '/assets/css/ai-model-bom.css' ), array( 'cyberdat-tools-common' ), cyberdat_theme_asset_version( '/assets/css/ai-model-bom.css' ) );
	wp_enqueue_script( 'cyberdat-ai-model-bom', get_theme_file_uri( '/assets/js/ai-model-bom/app.js' ), array(), cyberdat_theme_asset_version( '/assets/js/ai-model-bom/app.js' ), array( 'strategy' => 'defer', 'in_footer' => true ) );
}
add_action( 'wp_enqueue_scripts', 'cyberdat_bom_assets', 20 );
