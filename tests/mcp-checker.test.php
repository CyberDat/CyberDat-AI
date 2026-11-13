<?php
/** MCP Security & Policy Checker server contracts against narrow doubles: no WordPress, database or HTTP. */
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
function get_theme_file_path( $p ) { return __DIR__ . '/../wp-content/themes/cyberdat' . $p; }

require __DIR__ . '/../wp-content/themes/cyberdat/inc/tool-security.php';
require __DIR__ . '/../wp-content/themes/cyberdat/inc/tool-log-anonymizer.php';
require __DIR__ . '/../wp-content/themes/cyberdat/inc/tool-prompt-injection-detector.php';
require __DIR__ . '/../wp-content/themes/cyberdat/inc/tool-lotl-analyzer.php';
require __DIR__ . '/../wp-content/themes/cyberdat/inc/tool-mcp-checker.php';

function check( $ok, $label ) { if ( ! $ok ) { throw new RuntimeException( 'FAIL: ' . $label ); } echo 'PASS: ' . $label . "\n"; }

$GLOBALS['posts'][1] = (object) array( 'ID' => 1, 'post_type' => 'page', 'post_name' => 'tools', 'post_parent' => 0, 'template' => 'page-templates/tools.php' );
$GLOBALS['posts'][2] = (object) array( 'ID' => 2, 'post_type' => 'page', 'post_name' => 'mcp-security-checker', 'post_parent' => 1, 'template' => 'page-templates/tool.php' );
$GLOBALS['posts'][3] = (object) array( 'ID' => 3, 'post_type' => 'page', 'post_name' => 'mcp-security-checker', 'post_parent' => 0, 'template' => 'page-templates/tool.php' );
$GLOBALS['posts'][4] = (object) array( 'ID' => 4, 'post_type' => 'page', 'post_name' => 'lotl-command-analyzer', 'post_parent' => 1, 'template' => 'page-templates/tool.php' );
$GLOBALS['posts'][5] = (object) array( 'ID' => 5, 'post_type' => 'page', 'post_name' => 'mcp-security-checker', 'post_parent' => 1, 'template' => '' );

// Renderer registration ------------------------------------------------------
check( 'cyberdat_mcp_render' === apply_filters( 'cyberdat/tool/renderer', null, 2 ), 'renderer registered for /tools/mcp-security-checker/ with the Tool template' );
foreach ( array( 3 => 'outside the /tools/ hub', 5 => 'without the Tool template', 99 => 'for a missing post' ) as $id => $why ) {
	check( null === apply_filters( 'cyberdat/tool/renderer', null, $id ), "no renderer $why" );
}
check( 'cyberdat_lotl_render' === apply_filters( 'cyberdat/tool/renderer', null, 4 ), 'other tools keep their renderers' );

// Markup -----------------------------------------------------------------------
ob_start();
cyberdat_mcp_render( 2 );
$html = ob_get_clean();
check( str_contains( $html, 'data-mcp-checker' ) && str_contains( $html, 'mcp-checker/worker.js?ver=123&#038;ev=123' ), 'workspace renders with same-origin worker URL (engine version)' );
foreach ( array( 'How it works', 'Privacy', 'Limitations', 'Sources', 'The text you enter is never sent anywhere', 'the background worker is restarted and the browser downloads its static script files again', 'A review aid, not a guarantee.', 'no finding does not mean the configuration is safe', 'does not start servers or run commands', 'does not check the reputation of packages, images or domains online', 'does not audit server code', 'URLs found in your configuration are never opened or checked online', 'The policy leaves the tab only if you download it', 'Secret values are never displayed or exported in full', 'It does not contain the full configuration', 'Model Context Protocol specification', 'referenced here by name only', 'Security check', 'Policy check', 'Load example policy', 'Download policy', 'Policy settings', 'No corrected configuration is generated' ) as $needle ) {
	check( str_contains( $html, $needle ), "required text present: $needle" );
}
preg_match_all( '#<a\b[^>]*href="([^"]+)"[^>]*>#', $html, $links );
check( array() === $links[1], 'no links in the tool markup (sources are referenced by name only)' );
check( ! preg_match( '/<(?:img|iframe|script|link)\b/i', $html ), 'no auto-loading resources (img, iframe, script, link) in tool markup' );
check( ! preg_match( '/<form\b|action=|method=/i', $html ), 'no form can submit input to WordPress' );
check( ! preg_match( '/[\x{0400}-\x{04FF}]/u', $html ), 'interface text is English only' );
check( 2 === substr_count( $html, 'spellcheck="false"' ) && str_contains( $html, 'role="status"' ) && str_contains( $html, 'role="alert"' ), 'both text boxes opt out of spellcheck; live regions present' );
check( 2 === substr_count( $html, 'type="radio" name="cd-mcp-mode"' ) && str_contains( $html, '<legend' ), 'mode choice is a labelled radio group' );
libxml_use_internal_errors( true );
$doc = new DOMDocument();
check( $doc->loadHTML( '<!doctype html><meta charset="utf-8">' . $html ), 'markup parses as HTML' );
$xp = new DOMXPath( $doc );
$ids = array();
foreach ( $xp->query( '//*[@id]' ) as $node ) { $ids[] = $node->getAttribute( 'id' ); }
check( count( $ids ) === count( array_unique( $ids ) ), 'element ids are unique' );
foreach ( $xp->query( '//label[@for]' ) as $label ) { check( in_array( $label->getAttribute( 'for' ), $ids, true ), 'label for="' . $label->getAttribute( 'for' ) . '" targets an element' ); }

preg_match( '#id="cd-mcp-limits".*?<li>(.*?)</li>#s', $html, $first );
check( str_starts_with( $first[1] ?? '', 'TOML and YAML are not supported.' ), 'Limitations start with: TOML and YAML are not supported' );

// Versions -------------------------------------------------------------------------
$engine = file_get_contents( __DIR__ . '/../wp-content/themes/cyberdat/assets/js/mcp-checker/engine.js' );
preg_match( "/const VERSION = '([^']+)';\s*const RULESET_VERSION = '([^']+)';/", $engine, $v );
check( CYBERDAT_MCP_ENGINE === $v[1] && CYBERDAT_MCP_RULESET === $v[2] && str_contains( $html, 'Engine ' . $v[1] . ' · rules ' . $v[2] ), 'engine and rules versions shown on the page match engine.js' );

// Security headers and assets ------------------------------------------------------
$GLOBALS['queried'] = 2;
$csp = '';
foreach ( cyberdat_tool_security_header_lines() as $h ) { if ( str_starts_with( $h, 'Content-Security-Policy: ' ) ) { $csp = substr( $h, 25 ); } }
check( str_contains( $csp, "connect-src 'none'" ) && str_contains( $csp, "default-src 'none'" ) && str_contains( $csp, "worker-src 'self'" ) && ! preg_match( '#https?:|unsafe-eval#', $csp ), 'strict CSP on the checker page: no network connections, no external hosts' );
cyberdat_prompt_detector_assets();
cyberdat_log_anonymizer_assets();
cyberdat_lotl_assets();
check( array() === $GLOBALS['enqueued'], 'other tools do not load their assets on this page' );
cyberdat_mcp_assets();
check( array( 'cyberdat-tools-common', 'cyberdat-mcp-checker', 'cyberdat-mcp-checker' ) === array_column( $GLOBALS['enqueued'], 1 ), 'tools-common.css, own stylesheet and one deferred script' );
foreach ( $GLOBALS['enqueued'] as $asset ) { check( str_starts_with( $asset[2], 'https://staging.cyberdat.eu/wp-content/themes/cyberdat/assets/' ), 'asset is a first-party theme file: ' . basename( $asset[2] ) ); }
check( 'defer' === ( $GLOBALS['enqueued'][2][3]['strategy'] ?? '' ), 'script deferred' );
$GLOBALS['queried'] = 4;
$GLOBALS['enqueued'] = array();
cyberdat_mcp_assets();
check( array() === $GLOBALS['enqueued'], 'checker assets not loaded on other tool pages' );

// Catalogue ------------------------------------------------------------------------
$catalog = json_decode( file_get_contents( __DIR__ . '/../wp-content/themes/cyberdat/inc/tools-catalog.json' ), true );
check( 'mcp-security-checker' === $catalog[3]['slug'] && '/tools/mcp-security-checker/' === $catalog[3]['url'] && 'available' === $catalog[3]['status'] && '1.2' === $catalog[3]['release'] && 'MCP Security & Policy Checker' === $catalog[3]['title'], 'catalogue: tool 4 (first of release 1.2) points to /tools/mcp-security-checker/, name and release unchanged' );
$editorial = json_decode( file_get_contents( __DIR__ . '/../deploy/tools-mcp-checker/editorial.json' ), true );
check( is_array( $editorial ) && 'MCP Security & Policy Checker' === $editorial['title'] && ! preg_match( '/[\x{0400}-\x{04FF}]/u', implode( ' ', $editorial ) ), 'editorial fields: English, tool name unchanged' );
echo "All MCP Security & Policy Checker server checks passed.\n";
