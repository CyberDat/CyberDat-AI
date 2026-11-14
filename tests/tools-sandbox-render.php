<?php
/** Pure CLI renderer double. Does not load WordPress, plugins or a database. */
define( 'ABSPATH', __DIR__ . '/' );
$root = dirname( __DIR__ ) . '/wp-content/themes/cyberdat';
function add_action( ...$args ) {}
function add_filter( ...$args ) {}
function __( $s, $d = null ) { return $s; }
function esc_html__( $s, $d = null ) { return htmlspecialchars( $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8' ); }
function esc_html_e( $s, $d = null ) { echo esc_html__( $s, $d ); }
function esc_html( $s ) { return esc_html__( (string) $s ); }
function esc_attr( $s ) { return esc_html( $s ); }
function esc_attr_e( $s, $d = null ) { echo esc_attr( $s ); }
function esc_url( $s ) { return esc_html( $s ); }
function number_format_i18n( $n ) { return number_format( $n ); }
function get_theme_file_path( $p ) { global $root; return $root . $p; }
function get_theme_file_uri( $p ) { return '/wp-content/themes/cyberdat' . $p; }
function cyberdat_theme_asset_version( $p ) { return (string) filemtime( get_theme_file_path( $p ) ); }
function add_query_arg( $args, $url ) { return $url . '?' . http_build_query( $args ); }
function wp_json_encode( $v ) { return json_encode( $v ); }
function is_singular( $type ) { return true; }
function cyberdat_is_tool( $id ) { return true; }
function get_queried_object_id() { return 1; }
function get_template_part( $path ) { global $root; include $root . '/' . $path . '.php'; }
$map = array(
 'log-anonymizer' => array( 'tool-log-anonymizer.php', 'log-anonymizer' ),
 'prompt-injection-detector' => array( 'tool-prompt-injection-detector.php', 'prompt-injection-detector' ),
 'lotl-command-analyzer' => array( 'tool-lotl-analyzer.php', 'lotl-analyzer' ),
 'mcp-security-checker' => array( 'tool-mcp-checker.php', 'mcp-checker' ),
 'agent-leak-inspector' => array( 'tool-leak-inspector.php', 'leak-inspector' ),
);
$slug = $argv[1] ?? '';
if ( ! isset( $map[$slug] ) ) { exit( 2 ); }
require $root . '/inc/tool-security.php';
require $root . '/inc/' . $map[$slug][0];
ob_start();
echo '<!doctype html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>CyberDat local tool sandbox</title>';
foreach ( array( 'tokens.css', 'main.css', 'tools.css', 'tools-common.css', $map[$slug][1] . '.css' ) as $css ) {
 echo '<link rel="stylesheet" href="/wp-content/themes/cyberdat/assets/css/' . esc_attr( $css ) . '">';
}
echo '</head><body class="cyberdat"><main class="cyberdat-container"><article class="cyberdat-tool">';
include $root . '/template-parts/tools/' . $slug . '.php';
echo '</article></main><script src="/wp-content/themes/cyberdat/assets/js/' . esc_attr( $map[$slug][1] ) . '/app.js" defer></script></body></html>';
$html = ob_get_clean();
echo json_encode( array( 'headers' => cyberdat_tool_security_header_lines(), 'html' => $html ), JSON_THROW_ON_ERROR );
