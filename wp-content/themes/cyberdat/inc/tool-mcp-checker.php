<?php
/**
 * MCP Security & Policy Checker (Tools release 1.2, tool 4).
 *
 * Registers the reviewed renderer for the native page /tools/mcp-security-checker/ (URL from the
 * Stage 0.9 roadmap, confirmed by the owner at acceptance). Publication still requires the editorial
 * fields and the "reviewed" flag enforced by inc/tools.php. Uses the shared tool framework: strict CSP
 * (inc/tool-security.php), Web Worker, assets/css/tools-common.css. No external data is bundled.
 */
defined( 'ABSPATH' ) || exit;

const CYBERDAT_MCP_SLUG = 'mcp-security-checker';
const CYBERDAT_MCP_ENGINE = '1.0.0';
const CYBERDAT_MCP_RULESET = '2026-11-13.1';

/** True only for the tool page that is a direct child of the /tools/ hub. */
function cyberdat_mcp_is_page( $post_id ) {
	$post = get_post( $post_id );
	if ( ! $post || 'page' !== $post->post_type || CYBERDAT_MCP_SLUG !== $post->post_name || ! cyberdat_is_tool( $post->ID ) ) {
		return false;
	}
	$parent = $post->post_parent ? get_post( $post->post_parent ) : null;
	return $parent && 'tools' === $parent->post_name;
}

function cyberdat_mcp_renderer( $renderer, $post_id ) {
	return cyberdat_mcp_is_page( $post_id ) ? 'cyberdat_mcp_render' : $renderer;
}
add_filter( 'cyberdat/tool/renderer', 'cyberdat_mcp_renderer', 10, 2 );

function cyberdat_mcp_config() {
	$worker = '/assets/js/mcp-checker/worker.js';
	$engine = '/assets/js/mcp-checker/engine.js';
	return array(
		'worker'         => add_query_arg( array( 'ver' => cyberdat_theme_asset_version( $worker ), 'ev' => cyberdat_theme_asset_version( $engine ) ), get_theme_file_uri( $worker ) ),
		'engine_version' => CYBERDAT_MCP_ENGINE,
		'ruleset'        => CYBERDAT_MCP_RULESET,
	);
}

function cyberdat_mcp_render( $post_id ) {
	get_template_part( 'template-parts/tools/mcp-security-checker' );
}

function cyberdat_mcp_assets() {
	if ( ! is_singular( 'page' ) || ! cyberdat_mcp_is_page( get_queried_object_id() ) ) {
		return;
	}
	wp_enqueue_style( 'cyberdat-tools-common', get_theme_file_uri( '/assets/css/tools-common.css' ), array( 'cyberdat-tools' ), cyberdat_theme_asset_version( '/assets/css/tools-common.css' ) );
	wp_enqueue_style( 'cyberdat-mcp-checker', get_theme_file_uri( '/assets/css/mcp-checker.css' ), array( 'cyberdat-tools-common' ), cyberdat_theme_asset_version( '/assets/css/mcp-checker.css' ) );
	wp_enqueue_script( 'cyberdat-mcp-checker', get_theme_file_uri( '/assets/js/mcp-checker/app.js' ), array(), cyberdat_theme_asset_version( '/assets/js/mcp-checker/app.js' ), array( 'strategy' => 'defer', 'in_footer' => true ) );
}
add_action( 'wp_enqueue_scripts', 'cyberdat_mcp_assets', 20 );
