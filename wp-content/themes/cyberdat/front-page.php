<?php
/** Preview-only homepage: explicit isolated contexts; production falls back to index. */
defined( 'ABSPATH' ) || exit;
if ( ! cyberdat_home_preview_allowed() ) {
    require __DIR__ . '/index.php';
    return;
}
get_header();
?>
<div class="prototype-notice"><span class="sample-label">SAMPLE DATA</span><span><?php if(function_exists('cyberdat_research_active') && cyberdat_research_active()){esc_html_e('Editorial stories are SAMPLE DATA. Dashboard uses validated official cached data; NVD coverage is partial.','cyberdat');}else{esc_html_e( 'Design preview · Stories are SAMPLE DATA. Dashboard: fixed official CISA KEV snapshot, not live.', 'cyberdat' );} ?></span></div>
<div class="home-masthead"><h1><?php esc_html_e( 'Understand the threat.', 'cyberdat' ); ?> <span><?php esc_html_e( 'Stay ahead of it.', 'cyberdat' ); ?></span></h1><p>RESEARCH / CONTEXT / DEFENSE</p></div>
<?php get_template_part( 'template-parts/home/lead' ); ?>
<?php get_template_part( 'template-parts/home/intelligence' ); ?>
<?php cyberdat_editorial_section( __( 'Latest Analysis', 'cyberdat' ), 'BEYOND THE HEADLINE', 'editorial_format', ['analysis'], '/analysis/', 'analysis' ); ?>
<?php cyberdat_editorial_section( __( 'AI Security', 'cyberdat' ), 'THE NEXT SECURITY FRONTIER', 'category', ['ai-security'], '/topics/ai-security/', 'ai' ); ?>
<?php cyberdat_editorial_section( __( 'Guides & Learning', 'cyberdat' ), 'TURN INSIGHT INTO PRACTICE', 'editorial_format', ['guides', 'learning'], '/guides/', 'learning' ); ?>
<div class="home-closing"><span class="terminal-mark" aria-hidden="true">&gt;_</span><p><?php esc_html_e( 'Clarity in a complex threat landscape.', 'cyberdat' ); ?></p><span>CYBERDAT / SAMPLE EDITION</span></div>
<?php get_footer(); ?>
