<?php
/**
 * Template Name: Tool + SEO Content
 * Template Post Type: page
 */
defined( 'ABSPATH' ) || exit;
get_header();
while ( have_posts() ) :
	the_post();
	$data = cyberdat_tool_data( get_the_ID() );
	$ready = cyberdat_tool_ready( get_the_ID() );
	?>
	<article <?php post_class( 'cyberdat-tool content-column' ); ?>>
		<?php cyberdat_tools_breadcrumbs(); ?>
		<header><h1><?php echo esc_html( get_the_title() ); ?></h1><p class="cyberdat-tool-summary"><?php echo esc_html( $data['summary'] ); ?></p></header>
		<section class="cyberdat-tool-workspace" aria-label="<?php esc_attr_e( 'Interactive utility', 'cyberdat' ); ?>">
			<?php if ( $ready ) : ?>
				<?php call_user_func( cyberdat_tool_renderer( get_the_ID() ), get_the_ID() ); ?>
			<?php else : ?>
				<p role="status"><?php esc_html_e( 'Preview only — this tool is not available yet. No data is processed or submitted.', 'cyberdat' ); ?></p>
			<?php endif; ?>
		</section>
		<?php
		if ( '' !== trim( get_post_field( 'post_content', get_the_ID() ) ) ) : ?>
			<div class="cyberdat-tool-editorial"><?php the_content(); ?></div>
		<?php else :
		$sections = array( 'how_it_works' => __( 'How It Works', 'cyberdat' ), 'documentation' => __( 'Technical Documentation', 'cyberdat' ), 'examples' => __( 'Examples & Use Cases', 'cyberdat' ), 'faq' => __( 'FAQ', 'cyberdat' ) );
		foreach ( $sections as $key => $label ) :
			if ( '' === trim( $data[ $key ] ) ) { continue; }
			?>
			<section class="prose" aria-labelledby="tool-<?php echo esc_attr( $key ); ?>"><h2 id="tool-<?php echo esc_attr( $key ); ?>"><?php echo esc_html( $label ); ?></h2><?php echo wp_kses_post( wpautop( $data[ $key ] ) ); ?></section>
		<?php endforeach; endif; ?>
		<?php if ( $data['github'] ) : ?>
			<section><h2><?php esc_html_e( 'GitHub Source Code', 'cyberdat' ); ?></h2><a href="<?php echo esc_url( $data['github'] ); ?>" rel="noopener noreferrer"><?php esc_html_e( 'Review the source on GitHub', 'cyberdat' ); ?></a></section>
		<?php endif; ?>
		<?php cyberdat_tool_related_links(); ?>
	</article>
<?php endwhile; ?>
<?php get_footer(); ?>
