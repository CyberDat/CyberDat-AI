<?php
/**
 * MITRE ATLAS Attack Vector Mapper (Tools release 1.2, tool 7).
 *
 * Registers the reviewed renderer for the native page /tools/mitre-atlas-mapper/ (URL from the catalogue entry).
 * Publication still requires the editorial fields and the "reviewed" flag enforced by inc/tools.php. Uses the shared
 * tool framework: strict CSP (inc/tool-security.php), Web Worker, assets/css/tools-common.css. The MITRE ATLAS data
 * snapshot (Apache-2.0) is part of the theme; no model, MITRE site or other service is called.
 */
defined( 'ABSPATH' ) || exit;

const CYBERDAT_ATL_SLUG = 'mitre-atlas-mapper';
const CYBERDAT_ATL_ENGINE = '1.0.2';
const CYBERDAT_ATL_RULESET = '2026-11-15.1';
const CYBERDAT_ATL_DATA_RELEASE = '2026.10';
const CYBERDAT_ATL_DATA_DATE = '2026-10-28';
const CYBERDAT_ATL_DATA_COMMIT = 'f56c1468731d6428e5bf875263b4643b46d67437';

/** System properties offered in the System profile mode (keys and labels equal engine.js PROPERTIES; checked by tests). */
function cyberdat_atl_properties() {
	return array(
		'external-api'      => __( 'Uses an external model through an API', 'cyberdat' ),
		'own-model'         => __( 'Runs its own or a fine-tuned model', 'cyberdat' ),
		'rag'               => __( 'Retrieval (RAG) over external or user-supplied documents', 'cyberdat' ),
		'agent-tools'       => __( 'Agent that can call tools or take actions', 'cyberdat' ),
		'file-upload'       => __( 'Users can upload files that the AI processes', 'cyberdat' ),
		'public'            => __( 'Publicly accessible (no login, or open sign-up)', 'cyberdat' ),
		'training-pipeline' => __( 'Has a training or fine-tuning pipeline', 'cyberdat' ),
		'open-registry'     => __( 'Uses models or datasets from public registries', 'cyberdat' ),
	);
}

/** True only for the tool page that is a direct child of the /tools/ hub. */
function cyberdat_atl_is_page( $post_id ) {
	$post = get_post( $post_id );
	if ( ! $post || 'page' !== $post->post_type || CYBERDAT_ATL_SLUG !== $post->post_name || ! cyberdat_is_tool( $post->ID ) ) {
		return false;
	}
	$parent = $post->post_parent ? get_post( $post->post_parent ) : null;
	return $parent && 'tools' === $parent->post_name;
}

function cyberdat_atl_renderer( $renderer, $post_id ) {
	return cyberdat_atl_is_page( $post_id ) ? 'cyberdat_atl_render' : $renderer;
}
add_filter( 'cyberdat/tool/renderer', 'cyberdat_atl_renderer', 10, 2 );

function cyberdat_atl_config() {
	$worker = '/assets/js/atlas-mapper/worker.js';
	$engine = '/assets/js/atlas-mapper/engine.js';
	$data   = '/assets/js/atlas-mapper/atlas-data.js';
	return array(
		'worker'         => add_query_arg( array( 'ver' => cyberdat_theme_asset_version( $worker ), 'ev' => cyberdat_theme_asset_version( $engine ), 'dv' => cyberdat_theme_asset_version( $data ) ), get_theme_file_uri( $worker ) ),
		'engine_version' => CYBERDAT_ATL_ENGINE,
		'ruleset'        => CYBERDAT_ATL_RULESET,
		'data_release'   => CYBERDAT_ATL_DATA_RELEASE,
		'data_date'      => CYBERDAT_ATL_DATA_DATE,
		'data_commit'    => CYBERDAT_ATL_DATA_COMMIT,
	);
}

function cyberdat_atl_render( $post_id ) {
	get_template_part( 'template-parts/tools/mitre-atlas-mapper' );
}

function cyberdat_atl_assets() {
	if ( ! is_singular( 'page' ) || ! cyberdat_atl_is_page( get_queried_object_id() ) ) {
		return;
	}
	wp_enqueue_style( 'cyberdat-tools-common', get_theme_file_uri( '/assets/css/tools-common.css' ), array( 'cyberdat-tools' ), cyberdat_theme_asset_version( '/assets/css/tools-common.css' ) );
	wp_enqueue_style( 'cyberdat-atlas-mapper', get_theme_file_uri( '/assets/css/atlas-mapper.css' ), array( 'cyberdat-tools-common' ), cyberdat_theme_asset_version( '/assets/css/atlas-mapper.css' ) );
	wp_enqueue_script( 'cyberdat-atlas-mapper', get_theme_file_uri( '/assets/js/atlas-mapper/app.js' ), array(), cyberdat_theme_asset_version( '/assets/js/atlas-mapper/app.js' ), array( 'strategy' => 'defer', 'in_footer' => true ) );
}
add_action( 'wp_enqueue_scripts', 'cyberdat_atl_assets', 20 );
