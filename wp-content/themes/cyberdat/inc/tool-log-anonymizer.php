<?php
/**
 * Privacy Shield Log Anonymizer (Tools release 1.1, tool 1).
 *
 * Registers the reviewed renderer for the native page /tools/log-anonymizer/.
 * Publication still requires the editorial fields and the "reviewed" flag
 * enforced by inc/tools.php; this file only supplies the implementation.
 */
defined( 'ABSPATH' ) || exit;

const CYBERDAT_LOG_ANONYMIZER_SLUG = 'log-anonymizer';
const CYBERDAT_LOG_ANONYMIZER_ENGINE = '1.0.3';
const CYBERDAT_LOG_ANONYMIZER_RULESET = '2026-11-14.1';

/** True only for the tool page that is a direct child of the published-or-draft /tools/ hub. */
function cyberdat_log_anonymizer_is_page( $post_id ) {
	$post = get_post( $post_id );
	if ( ! $post || 'page' !== $post->post_type || CYBERDAT_LOG_ANONYMIZER_SLUG !== $post->post_name || ! cyberdat_is_tool( $post->ID ) ) {
		return false;
	}
	$parent = $post->post_parent ? get_post( $post->post_parent ) : null;
	return $parent && 'tools' === $parent->post_name;
}

function cyberdat_log_anonymizer_renderer( $renderer, $post_id ) {
	return cyberdat_log_anonymizer_is_page( $post_id ) ? 'cyberdat_log_anonymizer_render' : $renderer;
}
add_filter( 'cyberdat/tool/renderer', 'cyberdat_log_anonymizer_renderer', 10, 2 );

/** Category ids must match CATEGORIES in assets/js/log-anonymizer/engine.js (tested). */
function cyberdat_log_anonymizer_categories() {
	return array(
		'ipv4'       => array( 'label' => __( 'IPv4 addresses', 'cyberdat' ), 'short' => __( 'IPv4', 'cyberdat' ), 'example' => '203.0.113.7' ),
		'ipv6'       => array( 'label' => __( 'IPv6 addresses', 'cyberdat' ), 'short' => __( 'IPv6', 'cyberdat' ), 'example' => '2001:db8::1' ),
		'email'      => array( 'label' => __( 'Email addresses', 'cyberdat' ), 'short' => __( 'Email', 'cyberdat' ), 'example' => 'name@example.com' ),
		'mac'        => array( 'label' => __( 'MAC addresses', 'cyberdat' ), 'short' => __( 'MAC', 'cyberdat' ), 'example' => '00:1a:2b:3c:4d:5e' ),
		'jwt'        => array( 'label' => __( 'JSON Web Tokens', 'cyberdat' ), 'short' => __( 'JWT', 'cyberdat' ), 'example' => 'eyJhbGci…' ),
		'auth'       => array( 'label' => __( 'Authorization headers', 'cyberdat' ), 'short' => __( 'Authorization', 'cyberdat' ), 'example' => 'Bearer …, Basic …' ),
		'apiKey'     => array( 'label' => __( 'Cloud and service API keys', 'cyberdat' ), 'short' => __( 'API keys', 'cyberdat' ), 'example' => 'AKIA…, ghp_…, sk_live_…' ),
		'secret'     => array( 'label' => __( 'Passwords and secrets', 'cyberdat' ), 'short' => __( 'Secrets', 'cyberdat' ), 'example' => 'password=…, Cookie: …' ),
		'privateKey' => array( 'label' => __( 'Private key blocks', 'cyberdat' ), 'short' => __( 'Private keys', 'cyberdat' ), 'example' => '-----BEGIN … PRIVATE KEY-----' ),
		'username'   => array( 'label' => __( 'Usernames', 'cyberdat' ), 'short' => __( 'Usernames', 'cyberdat' ), 'example' => 'user=…, /home/…' ),
		'personName' => array( 'label' => __( 'Names in explicit person/contact fields', 'cyberdat' ), 'short' => __( 'Names', 'cyberdat' ), 'example' => 'person_name=…, full_name=…' ),
		'phone'      => array( 'label' => __( 'Telephone numbers in explicit contact fields', 'cyberdat' ), 'short' => __( 'Phones', 'cyberdat' ), 'example' => 'contact_phone=…, telephone=…' ),
		'host'       => array( 'label' => __( 'Hostnames and domains', 'cyberdat' ), 'short' => __( 'Hosts', 'cyberdat' ), 'example' => 'db01.example.com' ),
		'card'       => array( 'label' => __( 'Payment card numbers (Luhn-checked)', 'cyberdat' ), 'short' => __( 'Cards', 'cyberdat' ), 'example' => '4111 1111 1111 1111' ),
		'ssn'        => array( 'label' => __( 'US Social Security numbers', 'cyberdat' ), 'short' => __( 'US SSN', 'cyberdat' ), 'example' => '123-45-6789' ),
	);
}

function cyberdat_log_anonymizer_config() {
	$worker = '/assets/js/log-anonymizer/worker.js';
	$engine = '/assets/js/log-anonymizer/engine.js';
	return array(
		'worker'         => add_query_arg( array( 'ver' => cyberdat_theme_asset_version( $worker ), 'ev' => cyberdat_theme_asset_version( $engine ) ), get_theme_file_uri( $worker ) ),
		'categories'     => cyberdat_log_anonymizer_categories(),
		'engine_version' => CYBERDAT_LOG_ANONYMIZER_ENGINE,
		'ruleset'        => CYBERDAT_LOG_ANONYMIZER_RULESET,
	);
}

function cyberdat_log_anonymizer_render( $post_id ) {
	get_template_part( 'template-parts/tools/log-anonymizer' );
}

function cyberdat_log_anonymizer_assets() {
	if ( ! is_singular( 'page' ) || ! cyberdat_log_anonymizer_is_page( get_queried_object_id() ) ) {
		return;
	}
	wp_enqueue_style( 'cyberdat-tools-common', get_theme_file_uri( '/assets/css/tools-common.css' ), array( 'cyberdat-tools' ), cyberdat_theme_asset_version( '/assets/css/tools-common.css' ) );
	wp_enqueue_style( 'cyberdat-log-anonymizer', get_theme_file_uri( '/assets/css/log-anonymizer.css' ), array( 'cyberdat-tools-common' ), cyberdat_theme_asset_version( '/assets/css/log-anonymizer.css' ) );
	wp_enqueue_script( 'cyberdat-log-anonymizer', get_theme_file_uri( '/assets/js/log-anonymizer/app.js' ), array(), cyberdat_theme_asset_version( '/assets/js/log-anonymizer/app.js' ), array( 'strategy' => 'defer', 'in_footer' => true ) );
}
add_action( 'wp_enqueue_scripts', 'cyberdat_log_anonymizer_assets', 20 );
