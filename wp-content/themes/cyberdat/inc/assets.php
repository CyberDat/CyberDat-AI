<?php
/** First-party assets, loaded using WordPress APIs. */
defined( 'ABSPATH' ) || exit;

function cyberdat_theme_asset_version( $relative_path ) {
	$path = get_theme_file_path( $relative_path );
	return is_file( $path ) ? (string) filemtime( $path ) : wp_get_theme()->get( 'Version' );
}

function cyberdat_theme_enqueue_assets() {
	wp_enqueue_style( 'cyberdat-tokens', get_theme_file_uri( '/assets/css/tokens.css' ), array(), cyberdat_theme_asset_version( '/assets/css/tokens.css' ) );
	wp_enqueue_style( 'cyberdat-main', get_theme_file_uri( '/assets/css/main.css' ), array( 'cyberdat-tokens' ), cyberdat_theme_asset_version( '/assets/css/main.css' ) );
	if ( is_front_page() && defined( 'CYBERDAT_PLAYGROUND' ) && CYBERDAT_PLAYGROUND ) {
		wp_enqueue_style( 'cyberdat-home-prototype', get_theme_file_uri( '/assets/css/home-prototype.css' ), array( 'cyberdat-main' ), cyberdat_theme_asset_version( '/assets/css/home-prototype.css' ) );
	}
	wp_enqueue_script(
		'cyberdat-navigation',
		get_theme_file_uri( '/assets/js/navigation.js' ),
		array(),
		cyberdat_theme_asset_version( '/assets/js/navigation.js' ),
		array( 'strategy' => 'defer', 'in_footer' => true )
	);
}
add_action( 'wp_enqueue_scripts', 'cyberdat_theme_enqueue_assets' );
