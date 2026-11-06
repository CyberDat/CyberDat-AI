<?php
/** A real missing page retains WordPress's 404 status. */
defined( 'ABSPATH' ) || exit;
get_header();
?>
<section class="empty-state prose">
	<p class="eyebrow"><?php esc_html_e( 'Error 404', 'cyberdat' ); ?></p>
	<h1><?php esc_html_e( 'Page not found', 'cyberdat' ); ?></h1>
	<p><?php esc_html_e( 'The page may have moved. Try a search or return to the homepage.', 'cyberdat' ); ?></p>
	<?php get_search_form(); ?>
	<p><a href="<?php echo esc_url( home_url( '/' ) ); ?>"><?php esc_html_e( 'Back to home', 'cyberdat' ); ?></a></p>
</section>
<?php get_footer(); ?>
