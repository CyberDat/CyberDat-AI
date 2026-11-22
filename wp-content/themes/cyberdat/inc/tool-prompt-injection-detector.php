<?php
/**
 * Indirect Prompt Injection Sanitizer & Detector (Tools release 1.1, tool 2).
 *
 * Registers the reviewed renderer for the native page /tools/prompt-injection-detector/
 * (proposed URL, confirmed by the owner at acceptance). Publication still requires the
 * editorial fields and the "reviewed" flag enforced by inc/tools.php.
 *
 * Reuses the tool framework: the strict CSP from inc/tool-security.php applies to every
 * Tool page, and the shared .cd-la component styles come from assets/css/tools-common.css.
 */
defined( 'ABSPATH' ) || exit;

const CYBERDAT_PROMPT_DETECTOR_SLUG = 'prompt-injection-detector';
const CYBERDAT_PROMPT_DETECTOR_ENGINE = '1.0.2';
const CYBERDAT_PROMPT_DETECTOR_RULESET = '2026-11-14.1';

/** True only for the tool page that is a direct child of the /tools/ hub. */
function cyberdat_prompt_detector_is_page( $post_id ) {
	$post = get_post( $post_id );
	if ( ! $post || 'page' !== $post->post_type || CYBERDAT_PROMPT_DETECTOR_SLUG !== $post->post_name || ! cyberdat_is_tool( $post->ID ) ) {
		return false;
	}
	$parent = $post->post_parent ? get_post( $post->post_parent ) : null;
	return $parent && 'tools' === $parent->post_name;
}

function cyberdat_prompt_detector_renderer( $renderer, $post_id ) {
	return cyberdat_prompt_detector_is_page( $post_id ) ? 'cyberdat_prompt_detector_render' : $renderer;
}
add_filter( 'cyberdat/tool/renderer', 'cyberdat_prompt_detector_renderer', 10, 2 );

/** Group ids must match GROUPS in assets/js/prompt-injection-detector/engine.js (tested). */
function cyberdat_prompt_detector_groups() {
	return array(
		'role'         => array( 'label' => __( 'Role and boundary spoofing', 'cyberdat' ), 'example' => '<|im_start|>system, [INST], </context>' ),
		'override'     => array( 'label' => __( 'Instruction override', 'cyberdat' ), 'example' => __( '"Ignore all previous instructions" (English, German, Russian, French, Spanish)', 'cyberdat' ) ),
		'exfiltration' => array( 'label' => __( 'Tool calls and data exfiltration', 'cyberdat' ), 'example' => __( 'Markdown images with data in the URL, webhooks, curl', 'cyberdat' ) ),
		'hidden'       => array( 'label' => __( 'Hidden text', 'cyberdat' ), 'example' => __( 'Zero-width and tag characters, HTML comments, display:none', 'cyberdat' ) ),
		'encoded'      => array( 'label' => __( 'Encoded payloads', 'cyberdat' ), 'example' => __( 'Base64, hex, URL encoding, HTML and Unicode escapes', 'cyberdat' ) ),
		'obfuscation'  => array( 'label' => __( 'Obfuscation', 'cyberdat' ), 'example' => __( 'Look-alike letters, leetspeak, s p a c e d letters', 'cyberdat' ) ),
		'extraction'   => array( 'label' => __( 'System prompt and secret extraction', 'cyberdat' ), 'example' => __( '"Reveal your system prompt", "list your API keys"', 'cyberdat' ) ),
	);
}

function cyberdat_prompt_detector_config() {
	$worker = '/assets/js/prompt-injection-detector/worker.js';
	$engine = '/assets/js/prompt-injection-detector/engine.js';
	return array(
		'worker'         => add_query_arg( array( 'ver' => cyberdat_theme_asset_version( $worker ), 'ev' => cyberdat_theme_asset_version( $engine ) ), get_theme_file_uri( $worker ) ),
		'groups'         => cyberdat_prompt_detector_groups(),
		'engine_version' => CYBERDAT_PROMPT_DETECTOR_ENGINE,
		'ruleset'        => CYBERDAT_PROMPT_DETECTOR_RULESET,
	);
}

function cyberdat_prompt_detector_render( $post_id ) {
	get_template_part( 'template-parts/tools/prompt-injection-detector' );
}

function cyberdat_prompt_detector_assets() {
	if ( ! is_singular( 'page' ) || ! cyberdat_prompt_detector_is_page( get_queried_object_id() ) ) {
		return;
	}
	// Shared workspace components (panels, buttons, callouts, info blocks) used by every tool.
	wp_enqueue_style( 'cyberdat-tools-common', get_theme_file_uri( '/assets/css/tools-common.css' ), array( 'cyberdat-tools' ), cyberdat_theme_asset_version( '/assets/css/tools-common.css' ) );
	wp_enqueue_style( 'cyberdat-prompt-detector', get_theme_file_uri( '/assets/css/prompt-injection-detector.css' ), array( 'cyberdat-tools-common' ), cyberdat_theme_asset_version( '/assets/css/prompt-injection-detector.css' ) );
	wp_enqueue_script( 'cyberdat-prompt-detector', get_theme_file_uri( '/assets/js/prompt-injection-detector/app.js' ), array(), cyberdat_theme_asset_version( '/assets/js/prompt-injection-detector/app.js' ), array( 'strategy' => 'defer', 'in_footer' => true ) );
}
add_action( 'wp_enqueue_scripts', 'cyberdat_prompt_detector_assets', 20 );
