<?php
/** Basic archive card. */
defined( 'ABSPATH' ) || exit;
?>
<article id="post-<?php the_ID(); ?>" <?php post_class( 'content-card' ); ?>>
	<h2 class="content-card__title"><a href="<?php the_permalink(); ?>"><?php echo esc_html( get_the_title() ); ?></a></h2>
	<?php if ( 'post' === get_post_type() ) : ?>
		<time class="entry-date" datetime="<?php echo esc_attr( get_the_date( DATE_W3C ) ); ?>"><?php echo esc_html( get_the_date() ); ?></time>
	<?php endif; ?>
	<div class="entry-summary"><?php the_excerpt(); ?></div>
</article>
