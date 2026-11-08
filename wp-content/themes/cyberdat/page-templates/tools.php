<?php
/**
 * Template Name: Tools Directory
 * Template Post Type: page
 */
defined( 'ABSPATH' ) || exit;
get_header();
while ( have_posts() ) :
    the_post();
    $catalog = cyberdat_planned_tools();
    $categories = array();
    foreach ( $catalog as $tool ) { $categories[ $tool['category_slug'] ] = $tool['category']; }
    ?>
    <article <?php post_class( 'cyberdat-tool cyberdat-catalog' ); ?> data-tools-catalog>
        <?php cyberdat_tools_breadcrumbs(); ?>
        <header class="tools-catalog-heading">
            <p class="eyebrow"><?php esc_html_e( 'THE CYBERDAT TOOLKIT', 'cyberdat' ); ?></p>
            <h1><?php esc_html_e( 'CyberDat Security Tools', 'cyberdat' ); ?></h1>
            <p class="tools-catalog-subtitle"><?php esc_html_e( 'Free, privacy-focused utilities for cybersecurity professionals.', 'cyberdat' ); ?></p>
            <p class="tools-catalog-notice"><?php esc_html_e( 'Development roadmap — all 10 tools below are Coming Soon. No utility is available yet, and no input is collected or processed here.', 'cyberdat' ); ?></p>
        </header>
        <div class="tools-filters" role="group" aria-label="<?php esc_attr_e( 'Filter tools by category', 'cyberdat' ); ?>" data-tools-filters hidden>
            <button type="button" data-tools-filter="all" aria-pressed="true"><?php esc_html_e( 'All tools', 'cyberdat' ); ?></button>
            <?php foreach ( $categories as $slug => $label ) : ?>
                <button type="button" data-tools-filter="<?php echo esc_attr( $slug ); ?>" aria-pressed="false"><?php echo esc_html( $label ); ?></button>
            <?php endforeach; ?>
        </div>
        <p class="tools-catalog-count" role="status" aria-live="polite" aria-atomic="true" data-tools-count data-count-label="<?php esc_attr_e( 'tools shown', 'cyberdat' ); ?>"><?php esc_html_e( '10 planned tools · 3 releases', 'cyberdat' ); ?></p>
        <div class="cyberdat-tools-grid tools-roadmap-grid">
            <?php foreach ( $catalog as $tool ) : ?>
                <article class="cyberdat-tool-card tools-roadmap-card" data-tool-category="<?php echo esc_attr( $tool['category_slug'] ); ?>">
                    <div class="tools-card-top"><span class="tools-card-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="28" height="28" focusable="false"><path d="<?php echo esc_attr( $tool['icon_path'] ); ?>" /></svg></span><span class="tools-status"><?php esc_html_e( 'Coming Soon', 'cyberdat' ); ?></span></div>
                    <p class="tools-card-category"><?php echo esc_html( $tool['category'] ); ?></p>
                    <h2><?php echo esc_html( $tool['title'] ); ?></h2>
                    <p class="tools-card-description"><?php echo esc_html( $tool['description'] ); ?></p>
                    <p class="tools-card-release"><?php printf( esc_html__( 'Phase %1$d · Release %2$s', 'cyberdat' ), (int) $tool['phase'], esc_html( $tool['release'] ) ); ?></p>
                </article>
            <?php endforeach; ?>
        </div>
        <?php cyberdat_tool_related_links(); ?>
    </article>
<?php endwhile; ?>
<?php get_footer(); ?>
