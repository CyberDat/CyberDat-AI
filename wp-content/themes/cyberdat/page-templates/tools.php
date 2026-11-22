<?php
/**
 * Template Name: Tools Directory
 * Template Post Type: page
 * Hub-only presentation. Catalogue and reviewed WordPress readiness own availability.
 */
defined( 'ABSPATH' ) || exit;
wp_enqueue_style( 'cyberdat-tools-hub', get_theme_file_uri( '/assets/css/tools-hub.css' ), array( 'cyberdat-tools' ), cyberdat_theme_asset_version( '/assets/css/tools-hub.css' ) );
get_header();
while ( have_posts() ) :
    the_post();
    $catalog = cyberdat_planned_tools();
    $ready = array();
    foreach ( cyberdat_ready_tools() as $ready_post ) { $ready[ $ready_post->post_name ] = get_permalink( $ready_post ); }
    $groups = array( 'available' => array(), 'planned' => array() );
    $categories = array();
    foreach ( $catalog as $tool ) {
        $url = ( 'available' === $tool['status'] && isset( $ready[ $tool['slug'] ] ) ) ? $ready[ $tool['slug'] ] : '';
        $tool['ready_url'] = $url;
        $groups[ $url ? 'available' : 'planned' ][] = $tool;
        $key = $tool['category_slug'];
        if ( ! isset( $categories[ $key ] ) ) { $categories[ $key ] = array( 'label' => $tool['category'], 'count' => 0, 'icon' => $tool['icon_path'] ); }
        $categories[ $key ]['count']++;
    }
    ?>
    <article <?php post_class( 'cyberdat-tool cyberdat-catalog tools-command-hub' ); ?> data-tools-catalog>
        <?php cyberdat_tools_breadcrumbs(); ?>
        <header class="tools-hero">
            <div class="tools-hero-copy">
                <p class="eyebrow"><?php esc_html_e( 'CYBERSECURITY TOOLS HUB', 'cyberdat' ); ?></p>
                <h1><?php esc_html_e( 'Cybersecurity', 'cyberdat' ); ?> <span><?php esc_html_e( 'Tools', 'cyberdat' ); ?></span></h1>
                <p class="tools-hero-description"><?php esc_html_e( 'Practical tools for security analysis, threat detection, and AI security.', 'cyberdat' ); ?></p>
                <p class="tools-hero-label"><span aria-hidden="true"></span><?php esc_html_e( 'Your investigation. Your judgment.', 'cyberdat' ); ?></p>
            </div>
            <img class="tools-hero-art" src="<?php echo esc_url( get_theme_file_uri( '/assets/images/tools-hub/hero.svg' ) ); ?>" width="480" height="260" alt="" aria-hidden="true" decoding="async">
        </header>
        <div class="tools-command-bar">
            <div class="tools-filters" role="group" aria-label="<?php esc_attr_e( 'Filter tools by category', 'cyberdat' ); ?>" data-tools-filters hidden>
                <button type="button" data-tools-filter="all" aria-pressed="true"><span aria-hidden="true">⊞</span> <?php esc_html_e( 'All tools', 'cyberdat' ); ?> <span class="tools-filter-number" aria-hidden="true"><?php echo count( $catalog ); ?></span></button>
                <?php foreach ( $categories as $slug => $category ) : ?>
                    <button type="button" data-tools-filter="<?php echo esc_attr( $slug ); ?>" aria-pressed="false"><svg viewBox="0 0 24 24" width="17" height="17" aria-hidden="true" focusable="false"><path d="<?php echo esc_attr( $category['icon'] ); ?>" /></svg><?php echo esc_html( $category['label'] ); ?> <span class="tools-filter-number" aria-hidden="true"><?php echo (int) $category['count']; ?></span></button>
                <?php endforeach; ?>
            </div>
            <p class="tools-catalog-count" role="status" aria-live="polite" aria-atomic="true" data-tools-count data-count-label="<?php esc_attr_e( 'tools shown', 'cyberdat' ); ?>"><?php printf( esc_html__( '%1$d / %1$d tools shown', 'cyberdat' ), count( $catalog ) ); ?></p>
        </div>
        <?php foreach ( $groups as $group => $tools ) : if ( ! $tools ) { continue; } ?>
            <section class="tools-deck tools-deck--<?php echo esc_attr( $group ); ?>" aria-labelledby="tools-<?php echo esc_attr( $group ); ?>-heading" data-tools-group>
                <div class="tools-deck-heading"><h2 id="tools-<?php echo esc_attr( $group ); ?>-heading"><?php echo 'available' === $group ? esc_html__( 'Ready for your workflow', 'cyberdat' ) : esc_html__( 'On the roadmap', 'cyberdat' ); ?></h2><p><?php echo 'available' === $group ? esc_html__( 'Explore the tools. Review the results.', 'cyberdat' ) : esc_html__( 'More capabilities, thoughtfully in development.', 'cyberdat' ); ?></p></div>
                <div class="cyberdat-tools-grid tools-roadmap-grid tools-grid--<?php echo esc_attr( $group ); ?>">
                    <?php foreach ( $tools as $tool ) : $url = $tool['ready_url'];
                        $visual = '/assets/images/tools-hub/' . basename( $tool['slug'] ) . '.svg';
                        ?>
                        <article class="cyberdat-tool-card tools-roadmap-card<?php echo $url ? ' is-available' : ''; ?>" data-tool-category="<?php echo esc_attr( $tool['category_slug'] ); ?>" data-tool-slug="<?php echo esc_attr( $tool['slug'] ); ?>">
                            <div class="tools-card-top"><span class="tools-status"><?php echo $url ? esc_html__( 'Available', 'cyberdat' ) : esc_html__( 'Coming soon', 'cyberdat' ); ?></span><span class="tools-card-category"><?php echo esc_html( $tool['category'] ); ?></span></div>
                            <figure class="tools-card-visual">
                                <?php if ( is_file( get_theme_file_path( $visual ) ) ) : ?>
                                    <img src="<?php echo esc_url( get_theme_file_uri( $visual ) ); ?>" width="480" height="260" alt="" aria-hidden="true" decoding="async" loading="lazy">
                                <?php else : ?>
                                    <svg viewBox="0 0 24 24" width="96" height="96" aria-hidden="true" focusable="false"><path d="<?php echo esc_attr( $tool['icon_path'] ); ?>" /></svg>
                                <?php endif; ?>
                                <?php if ( $url ) : ?><figcaption><?php esc_html_e( 'Illustrative preview · not live results', 'cyberdat' ); ?></figcaption><?php endif; ?>
                            </figure>
                            <div class="tools-card-copy">
                                <h3><?php if ( $url ) : ?><a class="tools-card-link" href="<?php echo esc_url( $url ); ?>"><?php echo esc_html( $tool['title'] ); ?></a><?php else : ?><?php echo esc_html( $tool['title'] ); ?><?php endif; ?></h3>
                                <p class="tools-card-description"><?php echo esc_html( $tool['description'] ); ?></p>
                                <div class="tools-card-footer"><?php if ( $url ) : ?><span class="tools-card-action" aria-hidden="true"><?php esc_html_e( 'Open tool', 'cyberdat' ); ?><span class="tools-card-arrow">↗</span></span><?php else : ?><p class="tools-card-release"><?php printf( esc_html__( 'Phase %1$d · Release %2$s', 'cyberdat' ), (int) $tool['phase'], esc_html( $tool['release'] ) ); ?></p><?php endif; ?></div>
                            </div>
                        </article>
                    <?php endforeach; ?>
                </div>
            </section>
        <?php endforeach; ?>
        <aside class="tools-hub-note"><span aria-hidden="true">◇</span><p><?php esc_html_e( 'Use results as investigation aids, not safety guarantees. Preview illustrations contain synthetic examples. Planned tools do not accept input.', 'cyberdat' ); ?></p></aside>
        <?php cyberdat_tool_related_links(); ?>
    </article>
<?php endwhile; ?>
<?php get_footer(); ?>
