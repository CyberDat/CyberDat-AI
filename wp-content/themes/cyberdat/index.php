<?php
/** Minimal fallback; dedicated editorial templates follow in later stages. */
defined( 'ABSPATH' ) || exit;
get_header();
?>
<?php if ( ! is_singular() ) : ?>
	<header class="section-heading">
		<h1>
			<?php
			if ( is_search() ) {
				/* translators: %s: Search query. */
				printf( esc_html__( 'Search results for: %s', 'cyberdat' ), esc_html( get_search_query( false ) ) );
			} elseif ( is_archive() ) {
				echo esc_html( wp_strip_all_tags( get_the_archive_title() ) );
			} else {
				esc_html_e( 'Latest articles', 'cyberdat' );
			}
			?>
		</h1>
		<?php if ( is_archive() ) : ?>
			<div class="archive-description prose"><?php echo wp_kses_post( get_the_archive_description() ); ?></div>
			<?php if ( is_tax( 'editorial_format', array( 'guides', 'learning', 'analysis' ) ) ) { cyberdat_tools_hub_link(); } ?>
		<?php endif; ?>
	</header>
<?php endif; ?>

<?php if ( have_posts() ) : ?>
	<div class="<?php echo is_singular() ? 'content-column' : 'content-grid'; ?>">
		<?php
		while ( have_posts() ) {
			the_post();
			get_template_part( 'template-parts/content', is_singular() ? 'singular' : null );
		}
		?>
	</div>
	<?php
	if ( ! is_singular() ) {
		the_posts_pagination( array( 'mid_size' => 1, 'prev_text' => __( 'Previous', 'cyberdat' ), 'next_text' => __( 'Next', 'cyberdat' ) ) );
	}
	?>
<?php else : ?>
	<section class="empty-state prose">
		<h2><?php esc_html_e( 'No articles to display', 'cyberdat' ); ?></h2>
		<p><?php esc_html_e( 'Explore another section or search the site.', 'cyberdat' ); ?></p>
		<?php get_search_form(); ?>
	</section>
<?php endif; ?>
<?php get_footer(); ?>
