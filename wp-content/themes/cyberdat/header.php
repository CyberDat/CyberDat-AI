<?php
/** Shared document header. SEO output is delegated to WordPress and Rank Math. */
defined( 'ABSPATH' ) || exit;
?>
<!doctype html>
<html <?php language_attributes(); ?>>
<head>
	<meta charset="<?php bloginfo( 'charset' ); ?>">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<?php wp_head(); ?>
</head>
<body <?php body_class(); ?>>
<?php wp_body_open(); ?>
<a class="skip-link" href="#main-content"><?php esc_html_e( 'Skip to content', 'cyberdat' ); ?></a>
<header class="site-header">
	<div class="container header-layout">
		<a class="site-brand" href="<?php echo esc_url( home_url( '/' ) ); ?>" rel="home">
			<span class="site-brand__mark" aria-hidden="true">&gt;_</span>
			<span><?php echo esc_html( get_bloginfo( 'name' ) ); ?></span>
		</a>
		<button class="menu-toggle" type="button" aria-controls="site-navigation" aria-expanded="false" data-menu-toggle hidden>
			<?php esc_html_e( 'Menu', 'cyberdat' ); ?>
		</button>
		<nav id="site-navigation" class="site-navigation" aria-label="<?php esc_attr_e( 'Primary navigation', 'cyberdat' ); ?>">
			<?php
			wp_nav_menu(
				array(
					'theme_location' => 'primary', 'container' => false,
					'menu_class' => 'primary-menu', 'depth' => 1,
					'fallback_cb' => 'cyberdat_theme_primary_fallback',
				)
			);
			?>
			<div class="header-search"><?php get_search_form(); ?></div>
		</nav>
	</div>
</header>
<main id="main-content" class="site-main container" tabindex="-1">
