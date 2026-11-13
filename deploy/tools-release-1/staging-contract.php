<?php
/** CLI-only identity gate. Called before any mutation, including each restore. */
function cd_tools_identity_valid( $i ) {
	return array( 'cli' => true, 'sapi' => 'cli', 'root' => '/var/www/cyberdat-staging/public',
		'db' => 'cyberdat_staging', 'prefix' => 'stg_', 'environment' => 'staging',
		'home' => 'https://staging.cyberdat.eu', 'siteurl' => 'https://staging.cyberdat.eu',
		'stylesheet' => 'cyberdat', 'template' => 'cyberdat', 'capability' => true ) === $i;
}

function cd_tools_assert_staging() {
	global $wpdb;
	if ( ! defined( 'WP_CLI' ) || ! WP_CLI || ! defined( 'ABSPATH' ) || ! defined( 'DB_NAME' ) ) { throw new RuntimeException( 'Missing staging CLI context' ); }
	$ok = cd_tools_identity_valid( array( 'cli' => true, 'sapi' => PHP_SAPI, 'root' => realpath( ABSPATH ),
		'db' => DB_NAME, 'prefix' => $wpdb->prefix, 'environment' => wp_get_environment_type(),
		'home' => get_option( 'home' ), 'siteurl' => get_option( 'siteurl' ),
		'stylesheet' => get_option( 'stylesheet' ), 'template' => get_option( 'template' ),
		'capability' => current_user_can( 'manage_options' ) ) );
	if ( ! $ok ) { throw new RuntimeException( 'Tools staging identity/capability gate refused' ); }
}

function cd_tools_decisions( $mode, $slugs ) {
	cd_tools_assert_staging();
	if ( 'plan' === $mode ) { return; }
	$file = __DIR__ . '/authorization.json';
	if ( ! is_file( $file ) || is_link( $file ) || 0 !== fileowner( $file ) || ( fileperms( $file ) & 0027 ) ) {
		throw new RuntimeException( 'Missing private root-owned owner authorization' );
	}
	$a = json_decode( file_get_contents( $file ), true, 32, JSON_THROW_ON_ERROR );
	if ( 'https://staging.cyberdat.eu' !== ( $a['origin'] ?? null ) || true !== ( $a['install_approved'] ?? null )
		|| time() > ( $a['expires_epoch'] ?? 0 ) || ! hash_equals( $a['artifact_sha256'] ?? '', getenv( 'CYBERDAT_TOOLS_ARTIFACT_SHA256' ) ?: '' ) ) {
		throw new RuntimeException( 'Owner authorization target/artifact/expiry mismatch' );
	}
	$needed = array( 'draft' => array( 'D4', 'D9' ), 'reviewed' => array( 'D5' ), 'publish' => array( 'D2', 'D5', 'D11' ) );
	foreach ( $needed[$mode] ?? array( 'DENY' ) as $key ) {
		if ( true !== ( $a['decisions'][$key] ?? null ) ) { throw new RuntimeException( 'Unresolved decision: ' . $key ); }
	}
	foreach ( $slugs as $slug ) {
		if ( ! in_array( $slug, $a['page_approvals'][$mode] ?? array(), true ) ) { throw new RuntimeException( 'Page not approved for this action' ); }
		if ( 'lotl-command-analyzer' === $slug && 'publish' === $mode && ( true !== ( $a['decisions']['D6'] ?? null ) || true !== ( $a['decisions']['D7'] ?? null ) ) ) {
			throw new RuntimeException( 'LotL license/source decision missing' );
		}
	}
}
