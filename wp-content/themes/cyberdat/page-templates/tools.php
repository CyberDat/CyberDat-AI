<?php
/**
 * Template Name: Tools Directory
 * Template Post Type: page
 */
defined( 'ABSPATH' ) || exit;
get_header();
while ( have_posts() ) :
    the_post();
    // Only the current release is shown. A card is "Available" only when the catalogue marks it
    // available AND its native page passes the fail-closed readiness check in inc/tools.php.
    $current_release = '1.1';
    $catalog = array_values( array_filter( cyberdat_planned_tools(), static function ( $tool ) use ( $current_release ) { return $current_release === $tool['release']; } ) );
    $ready = array();
    foreach ( cyberdat_ready_tools() as $ready_post ) { $ready[ $ready_post->post_name ] = get_permalink( $ready_post ); }
    $available = 0;
    foreach ( $catalog as $tool ) { $available += ( 'available' === $tool['status'] && isset( $ready[ $tool['slug'] ] ) ) ? 1 : 0; }
    ?>
    <article <?php post_class( 'cyberdat-tool cyberdat-catalog' ); ?> data-tools-catalog>
        <?php cyberdat_tools_breadcrumbs(); ?>
        <header class="tools-catalog-heading">
            <p class="eyebrow"><?php esc_html_e( 'THE CYBERDAT TOOLKIT', 'cyberdat' ); ?></p>
            <h1><?php esc_html_e( 'CyberDat Security Tools', 'cyberdat' ); ?></h1>
            <p class="tools-catalog-subtitle"><?php esc_html_e( 'Free, privacy-focused utilities for cybersecurity professionals.', 'cyberdat' ); ?></p>
            <?php if ( $available ) : ?>
                <p class="tools-catalog-notice"><?php esc_html_e( 'Available tools run entirely in your browser: the tool code does not transmit the text you enter. Tools marked Coming soon are in development and do not accept input.', 'cyberdat' ); ?></p>
            <?php else : ?>
                <p class="tools-catalog-notice"><?php esc_html_e( 'The first release is in development. No tool is available yet, and no input is collected or processed here.', 'cyberdat' ); ?></p>
            <?php endif; ?>
        </header>
        <div class="cyberdat-tools-grid tools-roadmap-grid">
            <?php foreach ( $catalog as $tool ) :
                $url = ( 'available' === $tool['status'] && isset( $ready[ $tool['slug'] ] ) ) ? $ready[ $tool['slug'] ] : '';
                ?>
                <article class="cyberdat-tool-card tools-roadmap-card<?php echo $url ? ' is-available' : ''; ?>" data-tool-category="<?php echo esc_attr( $tool['category_slug'] ); ?>">
                    <div class="tools-card-top"><span class="tools-card-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="28" height="28" focusable="false"><path d="<?php echo esc_attr( $tool['icon_path'] ); ?>" /></svg></span><span class="tools-status"><?php echo $url ? esc_html__( 'Available', 'cyberdat' ) : esc_html__( 'Coming soon', 'cyberdat' ); ?></span></div>
                    <p class="tools-card-category"><?php echo esc_html( $tool['category'] ); ?></p>
                    <h2><?php if ( $url ) : ?><a class="tools-card-link" href="<?php echo esc_url( $url ); ?>"><?php echo esc_html( $tool['title'] ); ?></a><?php else : ?><?php echo esc_html( $tool['title'] ); ?><?php endif; ?></h2>
                    <p class="tools-card-description"><?php echo esc_html( $tool['description'] ); ?></p>
                    <p class="tools-card-release"><?php printf( esc_html__( 'Release %s', 'cyberdat' ), esc_html( $tool['release'] ) ); ?></p>
                </article>
            <?php endforeach; ?>
        </div>
        <p class="tools-catalog-more"><?php esc_html_e( 'More tools planned.', 'cyberdat' ); ?></p>
        <?php cyberdat_tool_related_links(); ?>
    </article>
<?php endwhile; ?>
<?php get_footer(); ?>
