<?php
/** Presentation support only; taxonomies and REST remain in the MU layer. */
defined( 'ABSPATH' ) || exit;

function cyberdat_theme_setup() {
	load_theme_textdomain( 'cyberdat', get_template_directory() . '/languages' );
	add_theme_support( 'title-tag' );
	add_theme_support( 'automatic-feed-links' );
	add_theme_support( 'post-thumbnails' );
	add_image_size( 'cyberdat-featured', 1280, 800, true );
	add_image_size( 'cyberdat-briefing', 192, 120, true );
	add_image_size( 'cyberdat-card', 640, 400, true );
	add_theme_support( 'responsive-embeds' );
	add_theme_support( 'align-wide' );
	add_theme_support( 'wp-block-styles' );
	add_theme_support( 'editor-styles' );
	add_theme_support( 'html5', array( 'search-form', 'comment-form', 'comment-list', 'gallery', 'caption', 'style', 'script', 'navigation-widgets' ) );
	add_editor_style( array( 'assets/css/tokens.css', 'assets/css/editor.css' ) );
	register_nav_menus(
		array(
			'primary' => __( 'Primary navigation', 'cyberdat' ),
			'footer'  => __( 'Footer navigation', 'cyberdat' ),
		)
	);
}
add_action( 'after_setup_theme', 'cyberdat_theme_setup' );
