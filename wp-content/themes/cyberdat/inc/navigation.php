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
	$hub = get_page_by_path( 'tools' );
	if ( $hub && 'publish' === $hub->post_status ) { cyberdat_theme_navigation_link( get_permalink( $hub ), __( 'Tools', 'cyberdat' ) ); }
	echo '</ul>';
}

/** Virtual menu item: preserve the six existing items without database edits. */
function cyberdat_tools_menu_item( $items, $args ) {
    if ( 'primary' !== ( $args->theme_location ?? '' ) ) { return $items; }
    $hub = get_page_by_path( 'tools' );
    if ( ! $hub || 'publish' !== $hub->post_status ) { return $items; }
    $url = get_permalink( $hub );
    preg_match_all( '/href=[\x22\x27]([^\x22\x27]+)[\x22\x27]/', $items, $links );
    foreach ( $links[1] as $link ) {
        $link = html_entity_decode( $link, ENT_QUOTES, 'UTF-8' );
        if ( untrailingslashit( $link ) === untrailingslashit( $url ) || untrailingslashit( $link ) === untrailingslashit( wp_parse_url( $url, PHP_URL_PATH ) ) ) { return $items; }
    }
    $current = is_page( $hub->ID );
    return $items . '<li class="menu-item cyberdat-tools-menu-item' . ( $current ? ' current-menu-item' : '' ) . '"><a href="' . esc_url( $url ) . '"' . ( $current ? ' aria-current="page"' : '' ) . '>' . esc_html__( 'Tools', 'cyberdat' ) . '</a></li>';
}
add_filter( 'wp_nav_menu_items', 'cyberdat_tools_menu_item', 10, 2 );
