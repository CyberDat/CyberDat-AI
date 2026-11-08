<?php
/**
 * Template Name: Tools Directory
 * Template Post Type: page
 */
defined( 'ABSPATH' ) || exit;
get_header();
while ( have_posts() ) :
	the_post();
	?>
	<article <?php post_class( 'cyberdat-tool' ); ?>>
		<?php cyberdat_tools_breadcrumbs(); ?>
		<header><h1><?php echo esc_html( get_the_title() ); ?></h1></header>
		<div class="prose content-column"><?php the_content(); ?></div>
		<?php $tools = cyberdat_ready_tools(); ?>
		<?php if ( $tools ) : ?>
			<div class="cyberdat-tools-grid">
			<?php foreach ( $tools as $tool ) : $data = cyberdat_tool_data( $tool->ID ); ?>
				<article class="cyberdat-tool-card"><h2><a href="<?php echo esc_url( get_permalink( $tool ) ); ?>"><?php echo esc_html( get_the_title( $tool ) ); ?></a></h2><p><?php echo esc_html( $data['summary'] ); ?></p></article>
			<?php endforeach; ?>
			</div>
		<?php else : ?>
			<p class="cyberdat-tool-workspace"><?php esc_html_e( 'Tools are in development. No interactive utilities are available yet.', 'cyberdat' ); ?></p>
		<?php endif; ?>
		<?php cyberdat_tool_related_links(); ?>
	</article>
<?php endwhile; ?>
<?php get_footer(); ?>
