<?php
/** Accessible core-compatible search form. */
defined( 'ABSPATH' ) || exit;
$search_id = wp_unique_id( 'cyberdat-search-' );
?>
<form role="search" method="get" class="search-form" action="<?php echo esc_url( home_url( '/' ) ); ?>">
	<label class="screen-reader-text" for="<?php echo esc_attr( $search_id ); ?>"><?php esc_html_e( 'Search CyberDat', 'cyberdat' ); ?></label>
	<input id="<?php echo esc_attr( $search_id ); ?>" type="search" name="s" value="<?php echo esc_attr( get_search_query( false ) ); ?>" placeholder="<?php esc_attr_e( 'Search articles…', 'cyberdat' ); ?>" required>
	<button type="submit"><?php esc_html_e( 'Search', 'cyberdat' ); ?></button>
</form>
