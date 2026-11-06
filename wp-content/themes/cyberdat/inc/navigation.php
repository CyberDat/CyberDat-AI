<?php
/** Semantic navigation with a safe fallback before menus are assigned. */
defined( 'ABSPATH' ) || exit;

function cyberdat_theme_navigation_link( $url, $label ) {
	printf( '<li><a href="%1$s">%2$s</a></li>', esc_url( $url ), esc_html( $label ) );
}

function cyberdat_theme_primary_fallback() {
	echo '<ul class="primary-menu">';
	cyberdat_theme_navigation_link( home_url( '/' ), __( 'Home', 'cyberdat' ) );
	$topics = get_page_by_path( 'topics' );
	if ( $topics && 'publish' === $topics->post_status ) {
		cyberdat_theme_navigation_link( get_permalink( $topics ), __( 'Topics', 'cyberdat' ) );
	}
	$formats = array(
		'news' => __( 'News', 'cyberdat' ), 'analysis' => __( 'Analysis', 'cyberdat' ),
		'guides' => __( 'Guides', 'cyberdat' ), 'learning' => __( 'Learning', 'cyberdat' ),
	);
	foreach ( $formats as $slug => $label ) {
		$term = get_term_by( 'slug', $slug, 'editorial_format' );
		$url  = $term ? get_term_link( $term ) : false;
		if ( $url && ! is_wp_error( $url ) ) {
			cyberdat_theme_navigation_link( $url, $label );
		}
	}
	echo '</ul>';
}
