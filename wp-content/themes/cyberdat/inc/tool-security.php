<?php
/**
 * Response hardening for pages that use the "Tool + SEO Content" template.
 *
 * Tools process sensitive input in the browser, so their pages get a strict
 * Content Security Policy: first-party scripts only (plus a per-response nonce
 * for WordPress' own inline scripts), no outbound connections from scripts,
 * no third-party fonts, frames or images.
 */
defined( 'ABSPATH' ) || exit;

function cyberdat_tool_security_applies() {
	return is_singular( 'page' ) && cyberdat_is_tool( get_queried_object_id() );
}

function cyberdat_tool_csp_nonce() {
	static $nonce = null;
	if ( null === $nonce ) {
		$nonce = rtrim( strtr( base64_encode( random_bytes( 18 ) ), '+/', '-_' ), '=' );
	}
	return $nonce;
}

/** The policy as a single header value. 'unsafe-inline' styles are kept for WordPress core inline CSS only. */
function cyberdat_tool_csp_policy() {
	$directives = array(
		'default-src'     => "'none'",
		'script-src'      => "'self' 'nonce-" . cyberdat_tool_csp_nonce() . "'",
		'style-src'       => "'self' 'unsafe-inline'",
		'img-src'         => "'self' data:",
		'font-src'        => "'self'",
		'connect-src'     => "'none'",
		'worker-src'      => "'self'",
		'manifest-src'    => "'self'",
		'media-src'       => "'none'",
		'object-src'      => "'none'",
		'frame-src'       => "'none'",
		'child-src'       => "'self'",
		'frame-ancestors' => "'self'",
		'base-uri'        => "'none'",
		'form-action'     => "'self'",
	);
	$parts = array();
	foreach ( $directives as $name => $value ) {
		$parts[] = $name . ' ' . $value;
	}
	return implode( '; ', $parts );
}

/** Header lines for tool pages; empty everywhere else. */
function cyberdat_tool_security_header_lines() {
	if ( ! cyberdat_tool_security_applies() ) {
		return array();
	}
	return array(
		'Content-Security-Policy: ' . cyberdat_tool_csp_policy(),
		'Referrer-Policy: no-referrer',
		'X-Content-Type-Options: nosniff',
		'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()',
		'Cross-Origin-Opener-Policy: same-origin',
	);
}

function cyberdat_tool_security_headers() {
	$lines = cyberdat_tool_security_header_lines();
	if ( ! $lines ) {
		return;
	}
	// The emoji helper downloads images from a third-party CDN; tool pages do not need it.
	remove_action( 'wp_head', 'print_emoji_detection_script', 7 );
	remove_action( 'wp_print_styles', 'print_emoji_styles' );
	remove_action( 'wp_enqueue_scripts', 'wp_enqueue_emoji_styles' );
	if ( headers_sent() ) {
		return;
	}
	foreach ( $lines as $line ) {
		header( $line );
	}
}
add_action( 'template_redirect', 'cyberdat_tool_security_headers', 20 );

/** Add the CSP nonce to WordPress-printed script tags (inline and external). */
function cyberdat_tool_script_nonce( $attributes ) {
	if ( did_action( 'template_redirect' ) && cyberdat_tool_security_applies() && is_array( $attributes ) ) {
		$attributes['nonce'] = cyberdat_tool_csp_nonce();
	}
	return $attributes;
}
add_filter( 'wp_inline_script_attributes', 'cyberdat_tool_script_nonce' );
add_filter( 'wp_script_attributes', 'cyberdat_tool_script_nonce' );
