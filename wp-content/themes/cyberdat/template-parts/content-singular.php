<?php
/** Gutenberg content fallback, without a final article layout. */
defined( 'ABSPATH' ) || exit;
?>
<article id="post-<?php the_ID(); ?>" <?php post_class(); ?>>
	<header class="entry-header"><h1><?php echo esc_html( get_the_title() ); ?></h1></header>
	<div class="entry-content prose">
		<?php
		// Core content filters render trusted blocks and permitted post HTML.
		the_content();
		wp_link_pages( array( 'before' => '<nav class="page-links" aria-label="' . esc_attr__( 'Article pages', 'cyberdat' ) . '">', 'after' => '</nav>' ) );
		?>
	</div>
	<?php if ( is_singular( 'post' ) ) { cyberdat_tools_hub_link(); } ?>
</article>
