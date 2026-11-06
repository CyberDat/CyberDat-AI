<?php
/** Shared footer. */
defined( 'ABSPATH' ) || exit;
?>
</main>
<footer class="site-footer">
	<div class="container footer-layout">
		<p class="footer-brand"><?php echo esc_html( get_bloginfo( 'name' ) ); ?></p>
		<?php if ( has_nav_menu( 'footer' ) ) : ?>
			<nav aria-label="<?php esc_attr_e( 'Footer navigation', 'cyberdat' ); ?>">
				<?php wp_nav_menu( array( 'theme_location' => 'footer', 'container' => false, 'menu_class' => 'footer-menu', 'depth' => 1, 'fallback_cb' => false ) ); ?>
			</nav>
		<?php endif; ?>
		<p class="copyright">
			<?php
			printf(
				/* translators: 1: Current year, 2: Site name. */
				esc_html__( '© %1$s %2$s. All rights reserved.', 'cyberdat' ),
				esc_html( wp_date( 'Y' ) ),
				esc_html( get_bloginfo( 'name' ) )
			);
			?>
		</p>
	</div>
</footer>
<?php wp_footer(); ?>
</body>
</html>
