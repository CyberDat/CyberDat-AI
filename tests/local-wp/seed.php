<?php
/**
 * Local-only seed for the disposable cyberdat-tools-dev WordPress.
 * Usage inside the container: php seed.php install|pages
 * Refuses to run unless the site URL is a 127.0.0.1 address and environment is "local".
 */
if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}
$phase = $argv[1] ?? '';
define( 'WP_USE_THEMES', false );
if ( 'install' === $phase ) {
	define( 'WP_INSTALLING', true ); // Otherwise wp-load redirects to install.php and exits silently.
}
$_SERVER['HTTP_HOST'] = '127.0.0.1';
require '/var/www/html/wp-load.php';

if ( 'local' !== wp_get_environment_type() || ! preg_match( '#^http://127\.0\.0\.1:\d+$#', WP_HOME ) ) {
	fwrite( STDERR, "Refusing: not the local disposable site.\n" );
	exit( 2 );
}

add_filter( 'pre_wp_mail', '__return_false' );

if ( 'install' === $phase ) {
	require_once ABSPATH . 'wp-admin/includes/upgrade.php';
	if ( ! is_blog_installed() ) {
		// Random admin password, never printed. The local site is accessed anonymously.
		wp_install( 'CyberDat Local', 'localadmin', 'localadmin@example.invalid', false, '', wp_generate_password( 32, true, true ) );
	}
	update_option( 'blog_public', '0' );
	update_option( 'permalink_structure', '/%postname%/' );
	switch_theme( 'cyberdat' );
	echo "installed; theme=" . get_stylesheet() . "\n";
	exit( 0 );
}

if ( 'pages' === $phase ) {
	global $wp_rewrite;
	$wp_rewrite->set_permalink_structure( '/%postname%/' );
	$wp_rewrite->flush_rules( false );
	$hub = get_page_by_path( 'tools' );
	if ( ! $hub ) {
		$hub_id = wp_insert_post( array( 'post_type' => 'page', 'post_status' => 'publish', 'post_title' => 'Tools', 'post_name' => 'tools', 'meta_input' => array( '_wp_page_template' => 'page-templates/tools.php' ) ) );
	} else {
		$hub_id = $hub->ID;
	}
	$copy = json_decode( file_get_contents( __DIR__ . '/editorial.json' ), true );
	if ( ! is_array( $copy ) ) {
		fwrite( STDERR, 'editorial.json is not valid JSON: ' . json_last_error_msg() . PHP_EOL );
		exit( 3 );
	}
	$meta = array( 'reviewed' => true );
	foreach ( array( 'summary', 'how_it_works', 'documentation', 'examples', 'faq' ) as $key ) {
		$meta[ $key ] = $copy[ $key ];
	}
	$tool = get_page_by_path( 'tools/log-anonymizer' );
	$tool_id = $tool ? $tool->ID : wp_insert_post( array( 'post_type' => 'page', 'post_status' => 'draft', 'post_title' => $copy['title'], 'post_name' => 'log-anonymizer', 'post_parent' => $hub_id, 'meta_input' => array( '_wp_page_template' => 'page-templates/tool.php' ) ) );
	update_post_meta( $tool_id, '_cyberdat_tool', cyberdat_tool_sanitize( $meta ) );
	wp_update_post( array( 'ID' => $tool_id, 'post_title' => $copy['title'], 'post_status' => 'publish' ) );
	// Indirect Prompt Injection Sanitizer & Detector (tool 2), same publication path.
	$pi_copy = json_decode( (string) file_get_contents( __DIR__ . '/editorial-prompt-injection-detector.json' ), true );
	if ( is_array( $pi_copy ) ) {
		$pi_meta = array( 'reviewed' => true );
		foreach ( array( 'summary', 'how_it_works', 'documentation', 'examples', 'faq' ) as $key ) {
			$pi_meta[ $key ] = $pi_copy[ $key ];
		}
		$pi = get_page_by_path( 'tools/prompt-injection-detector' );
		$pi_id = $pi ? $pi->ID : wp_insert_post( array( 'post_type' => 'page', 'post_status' => 'draft', 'post_title' => $pi_copy['title'], 'post_name' => 'prompt-injection-detector', 'post_parent' => $hub_id, 'meta_input' => array( '_wp_page_template' => 'page-templates/tool.php' ) ) );
		update_post_meta( $pi_id, '_cyberdat_tool', cyberdat_tool_sanitize( $pi_meta ) );
		wp_update_post( array( 'ID' => $pi_id, 'post_title' => $pi_copy['title'], 'post_status' => 'publish' ) );
		printf( "tool=%s status=%s ready=%s
", get_permalink( $pi_id ), get_post_status( $pi_id ), cyberdat_tool_ready( $pi_id ) ? 'yes' : 'no' );
	}
	// An unfinished second tool proves the publication guard still fails closed.
	if ( ! get_page_by_path( 'tools/lolbas-analyzer' ) ) {
		$other = wp_insert_post( array( 'post_type' => 'page', 'post_status' => 'draft', 'post_title' => 'LotL / LOLBAS Command Analyzer', 'post_name' => 'lolbas-analyzer', 'post_parent' => $hub_id, 'meta_input' => array( '_wp_page_template' => 'page-templates/tool.php', '_cyberdat_tool' => array( 'reviewed' => true ) ) ) );
		wp_update_post( array( 'ID' => $other, 'post_status' => 'publish' ) );
	}
	printf( "tool=%s status=%s ready=%s lolbas_status=%s\n", get_permalink( $tool_id ), get_post_status( $tool_id ), cyberdat_tool_ready( $tool_id ) ? 'yes' : 'no', get_post_status( get_page_by_path( 'tools/lolbas-analyzer' ) ) );
	exit( 0 );
}

fwrite( STDERR, "Usage: php seed.php install|pages\n" );
exit( 64 );
