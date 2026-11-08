<?php
/** Template Name: CyberDat Threat Intelligence */
defined('ABSPATH') || exit;
if(!cyberdat_is_intelligence_page()){status_header(404);nocache_headers();get_template_part('404');return;}
get_header();
?>
<header class="ti-page-header"><p class="eyebrow">RESEARCH / EVIDENCE / CONTEXT</p><h1><?php esc_html_e('Threat Intelligence','cyberdat'); ?></h1><p><?php esc_html_e('Explore verified vulnerability intelligence and transparent source coverage. Geographic observations are separate from vulnerability catalogs.','cyberdat'); ?></p><nav aria-label="Intelligence sections"><a href="#global-threat-map">Global Threat Map</a><a href="#threat-dashboard">Intelligence Overview</a><a href="<?php echo esc_url(home_url('/guides/')); ?>">Security Guides</a></nav></header>
<?php get_template_part('template-parts/threat-map');get_template_part('template-parts/home/threat-dashboard');get_footer(); ?>
