<?php
/** Log Anonymizer server contracts against narrow doubles: no WordPress, database or HTTP. */
define( 'ABSPATH', __DIR__ . '/' );
$GLOBALS['filters'] = array(); $GLOBALS['actions'] = array(); $GLOBALS['posts'] = array(); $GLOBALS['headers'] = array();
$GLOBALS['enqueued'] = array(); $GLOBALS['queried'] = 0; $GLOBALS['singular'] = true; $GLOBALS['removed'] = array(); $GLOBALS['template_redirect_done'] = false;
function add_action( $hook, $fn, $priority = 10, $args = 1 ) { $GLOBALS['actions'][ $hook ][] = $fn; }
function add_filter( $hook, $fn, $priority = 10, $args = 1 ) { $GLOBALS['filters'][ $hook ][] = $fn; }
function apply_filters( $hook, $value, ...$args ) { foreach ( $GLOBALS['filters'][ $hook ] ?? array() as $fn ) { $value = $fn( $value, ...$args ); } return $value; }
function remove_action( $hook, $fn, $priority = 10 ) { $GLOBALS['removed'][] = $hook . ':' . $fn; return true; }
function did_action( $hook ) { return 'template_redirect' === $hook && $GLOBALS['template_redirect_done'] ? 1 : 0; }
function get_post( $id ) { return $GLOBALS['posts'][ $id ] ?? null; }
function get_page_template_slug( $id ) { return $GLOBALS['posts'][ $id ]->template ?? ''; }
function is_singular( $type = '' ) { return $GLOBALS['singular']; }
function get_queried_object_id() { return $GLOBALS['queried']; }
function __( $s, $d = null ) { return $s; }
function esc_html( $s ) { return htmlspecialchars( (string) $s, ENT_QUOTES, 'UTF-8' ); }
function esc_attr( $s ) { return esc_html( $s ); }
function esc_url( $s ) { return htmlspecialchars( str_replace( '&', '&#038;', (string) $s ), ENT_QUOTES, 'UTF-8', false ); }
function esc_html_e( $s, $d = null ) { echo esc_html( $s ); }
function esc_attr_e( $s, $d = null ) { echo esc_attr( $s ); }
function esc_html__( $s, $d = null ) { return esc_html( $s ); }
function esc_attr__( $s, $d = null ) { return esc_attr( $s ); }
function get_theme_file_uri( $p ) { return 'https://staging.cyberdat.eu/wp-content/themes/cyberdat' . $p; }
function get_template_directory_uri() { return 'https://staging.cyberdat.eu/wp-content/themes/cyberdat'; }
function cyberdat_theme_asset_version( $p ) { return '123'; }
function add_query_arg( $args, $url ) { return $url . '?' . http_build_query( $args ); }
function wp_enqueue_style( $h, $src, $deps = array(), $ver = false ) { $GLOBALS['enqueued'][] = array( 'style', $h, $src, $deps ); }
function wp_enqueue_script( $h, $src, $deps = array(), $ver = false, $args = array() ) { $GLOBALS['enqueued'][] = array( 'script', $h, $src, $args ); }
function get_template_part( $slug ) { require __DIR__ . '/../wp-content/themes/cyberdat/' . $slug . '.php'; }
function cyberdat_is_tool( $id ) { return 'page-templates/tool.php' === get_page_template_slug( $id ); }

require __DIR__ . '/../wp-content/themes/cyberdat/inc/tool-security.php';
require __DIR__ . '/../wp-content/themes/cyberdat/inc/tool-log-anonymizer.php';

function check( $ok, $label ) { if ( ! $ok ) { throw new RuntimeException( 'FAIL: ' . $label ); } echo 'PASS: ' . $label . "\n"; }

$GLOBALS['posts'][1] = (object) array( 'ID' => 1, 'post_type' => 'page', 'post_name' => 'tools', 'post_parent' => 0, 'template' => 'page-templates/tools.php' );
$GLOBALS['posts'][2] = (object) array( 'ID' => 2, 'post_type' => 'page', 'post_name' => 'log-anonymizer', 'post_parent' => 1, 'template' => 'page-templates/tool.php' );
$GLOBALS['posts'][3] = (object) array( 'ID' => 3, 'post_type' => 'page', 'post_name' => 'log-anonymizer', 'post_parent' => 0, 'template' => 'page-templates/tool.php' );
$GLOBALS['posts'][4] = (object) array( 'ID' => 4, 'post_type' => 'page', 'post_name' => 'log-anonymizer', 'post_parent' => 1, 'template' => '' );
$GLOBALS['posts'][5] = (object) array( 'ID' => 5, 'post_type' => 'page', 'post_name' => 'lolbas-analyzer', 'post_parent' => 1, 'template' => 'page-templates/tool.php' );
$GLOBALS['posts'][6] = (object) array( 'ID' => 6, 'post_type' => 'post', 'post_name' => 'log-anonymizer', 'post_parent' => 1, 'template' => 'page-templates/tool.php' );
$GLOBALS['posts'][7] = (object) array( 'ID' => 7, 'post_type' => 'page', 'post_name' => 'about', 'post_parent' => 0, 'template' => '' );

// Renderer registration ------------------------------------------------------
check( 'cyberdat_log_anonymizer_render' === apply_filters( 'cyberdat/tool/renderer', null, 2 ), 'renderer registered for /tools/log-anonymizer/ with the Tool template' );
foreach ( array( 3 => 'outside the /tools/ hub', 4 => 'without the Tool template', 5 => 'for a different tool', 6 => 'for a post with the same slug', 99 => 'for a missing post' ) as $id => $why ) {
	check( null === apply_filters( 'cyberdat/tool/renderer', null, $id ), "no renderer $why" );
}
$other = static function () {};
check( $other === apply_filters( 'cyberdat/tool/renderer', $other, 5 ), 'renderer of another tool is preserved' );

// Markup -----------------------------------------------------------------------
ob_start();
cyberdat_log_anonymizer_render( 2 );
$html = ob_get_clean();
check( str_contains( $html, 'data-log-anonymizer' ) && str_contains( $html, 'data-worker-src="https://staging.cyberdat.eu/wp-content/themes/cyberdat/assets/js/log-anonymizer/worker.js?ver=123&#038;ev=123"' ), 'workspace renders with same-origin worker URL' );
check( 13 === substr_count( $html, 'data-la-category' ), 'all 13 built-in categories rendered as checkboxes' );
foreach ( array( 'How it works', 'Privacy', 'Limitations of automated analysis', 'Automated anonymization cannot guarantee', 'Contains the original values.' ) as $needle ) {
	check( str_contains( $html, $needle ), "required block present: $needle" );
}
check( ! preg_match( '/<form\b|action=|method=/i', $html ), 'no form can submit input to WordPress' );
check( ! preg_match( '#(src|href)=["\']https?://(?!staging\.cyberdat\.eu/)#i', $html ), 'no third-party resource URLs in markup' );
check( ! preg_match( '/<script\b(?![^>]*type="?text\/template)/i', $html ), 'no inline script in tool markup' );
check( substr_count( $html, 'spellcheck="false"' ) >= 3 && str_contains( $html, 'data-gramm="false"' ) && str_contains( $html, 'autocomplete="off"' ), 'input fields opt out of cloud spellcheck, grammar extensions and autofill' );
check( str_contains( $html, 'role="status"' ) && str_contains( $html, 'role="alert"' ) && str_contains( $html, 'aria-live="polite"' ), 'live regions for status and errors' );
check( preg_match_all( '/<input[^>]*type="(?:checkbox|radio|file|text)"/', $html ) === preg_match_all( '/<input[^>]*type="(?:checkbox|radio|file|text)"[^>]*>/', $html ), 'inputs are well formed' );
check( ! preg_match( '/[\x{0400}-\x{04FF}]/u', $html ), 'interface text is English only' );
libxml_use_internal_errors( true );
$doc = new DOMDocument();
check( $doc->loadHTML( '<!doctype html><meta charset="utf-8">' . $html ), 'markup parses as HTML' );
$ids = array();
foreach ( ( new DOMXPath( $doc ) )->query( '//*[@id]' ) as $node ) { $ids[] = $node->getAttribute( 'id' ); }
check( count( $ids ) === count( array_unique( $ids ) ), 'element ids are unique' );
foreach ( ( new DOMXPath( $doc ) )->query( '//label[@for]' ) as $label ) {
	check( in_array( $label->getAttribute( 'for' ), $ids, true ), 'label for="' . $label->getAttribute( 'for' ) . '" targets an element' );
}

// Security headers -----------------------------------------------------------
$GLOBALS['queried'] = 7;
check( array() === cyberdat_tool_security_header_lines(), 'ordinary pages receive no tool CSP' );
$GLOBALS['queried'] = 2;
$GLOBALS['headers'] = cyberdat_tool_security_header_lines();
cyberdat_tool_security_headers(); // CLI: header() is a no-op, emoji hooks are removed.
$csp = '';
foreach ( $GLOBALS['headers'] as $h ) { if ( str_starts_with( $h, 'Content-Security-Policy: ' ) ) { $csp = substr( $h, 25 ); } }
$dir = array();
foreach ( explode( ';', $csp ) as $part ) { $bits = preg_split( '/\s+/', trim( $part ), 2 ); $dir[ $bits[0] ] = $bits[1] ?? ''; }
check( "'none'" === $dir['default-src'] && "'none'" === $dir['connect-src'] && "'none'" === $dir['object-src'] && "'none'" === $dir['base-uri'], 'CSP: default, connect, object and base-uri are none' );
check( (bool) preg_match( "/^'self' 'nonce-[A-Za-z0-9_-]{24}'$/", $dir['script-src'] ), 'CSP: scripts only from self plus per-response nonce' );
check( "'self'" === $dir['worker-src'] && "'self'" === $dir['font-src'] && "'self' data:" === $dir['img-src'], 'CSP: worker, font and image sources restricted to self' );
check( ! preg_match( '#https?:|\*#', $csp ) && ! str_contains( $dir['script-src'], 'unsafe' ), 'CSP: no external host, wildcard or unsafe script source' );
check( in_array( 'Referrer-Policy: no-referrer', $GLOBALS['headers'], true ) && in_array( 'X-Content-Type-Options: nosniff', $GLOBALS['headers'], true ), 'referrer and MIME sniffing headers sent' );
check( in_array( 'wp_head:print_emoji_detection_script', $GLOBALS['removed'], true ), 'third-party emoji loader removed on tool pages' );
$GLOBALS['template_redirect_done'] = true;
$attrs = apply_filters( 'wp_inline_script_attributes', array( 'id' => 'x' ) );
check( $attrs['nonce'] === cyberdat_tool_csp_nonce() && $attrs['id'] === 'x', 'WordPress inline scripts receive the CSP nonce' );
$GLOBALS['queried'] = 7;
check( ! isset( apply_filters( 'wp_script_attributes', array( 'id' => 'x' ) )['nonce'] ), 'no nonce added outside tool pages' );

// Assets -------------------------------------------------------------------------
$GLOBALS['queried'] = 5;
cyberdat_log_anonymizer_assets();
check( array() === $GLOBALS['enqueued'], 'assets not loaded on other tool pages' );
$GLOBALS['queried'] = 2;
cyberdat_log_anonymizer_assets();
$handles = array_column( $GLOBALS['enqueued'], 1 );
check( array( 'cyberdat-log-anonymizer', 'cyberdat-log-anonymizer' ) === $handles, 'one stylesheet and one deferred script on the tool page' );
foreach ( $GLOBALS['enqueued'] as $asset ) { check( str_starts_with( $asset[2], 'https://staging.cyberdat.eu/wp-content/themes/cyberdat/assets/' ), 'asset is a first-party theme file: ' . basename( $asset[2] ) ); }
check( 'defer' === $GLOBALS['enqueued'][1][3]['strategy'], 'script deferred' );
echo "All Log Anonymizer server checks passed.\n";
