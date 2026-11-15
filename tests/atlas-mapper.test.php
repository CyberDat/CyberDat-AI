<?php
/** MITRE ATLAS Attack Vector Mapper server contracts against narrow doubles: no WordPress, database or HTTP. */
define( 'ABSPATH', __DIR__ . '/' );
$GLOBALS['filters'] = array(); $GLOBALS['actions'] = array(); $GLOBALS['posts'] = array(); $GLOBALS['enqueued'] = array(); $GLOBALS['queried'] = 0; $GLOBALS['singular'] = true;
function add_action( $hook, $fn, $priority = 10, $args = 1 ) { $GLOBALS['actions'][ $hook ][] = $fn; }
function add_filter( $hook, $fn, $priority = 10, $args = 1 ) { $GLOBALS['filters'][ $hook ][] = $fn; }
function apply_filters( $hook, $value, ...$args ) { foreach ( $GLOBALS['filters'][ $hook ] ?? array() as $fn ) { $value = $fn( $value, ...$args ); } return $value; }
function remove_action( $hook, $fn, $priority = 10 ) { return true; }
function did_action( $hook ) { return 0; }
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
function get_theme_file_path( $p ) { return __DIR__ . '/../wp-content/themes/cyberdat' . $p; }
function cyberdat_theme_asset_version( $p ) { return '123'; }
function add_query_arg( $args, $url ) { return $url . '?' . http_build_query( $args ); }
function wp_enqueue_style( $h, $src, $deps = array(), $ver = false ) { $GLOBALS['enqueued'][] = array( 'style', $h, $src, $deps ); }
function wp_enqueue_script( $h, $src, $deps = array(), $ver = false, $args = array() ) { $GLOBALS['enqueued'][] = array( 'script', $h, $src, $args ); }
function get_template_part( $slug ) { require __DIR__ . '/../wp-content/themes/cyberdat/' . $slug . '.php'; }
function cyberdat_is_tool( $id ) { return 'page-templates/tool.php' === get_page_template_slug( $id ); }

require __DIR__ . '/../wp-content/themes/cyberdat/inc/tool-security.php';
require __DIR__ . '/../wp-content/themes/cyberdat/inc/tool-mcp-checker.php';
require __DIR__ . '/../wp-content/themes/cyberdat/inc/tool-atlas-mapper.php';

function check( $ok, $label ) { if ( ! $ok ) { throw new RuntimeException( 'FAIL: ' . $label ); } echo 'PASS: ' . $label . "\n"; }

$GLOBALS['posts'][1] = (object) array( 'ID' => 1, 'post_type' => 'page', 'post_name' => 'tools', 'post_parent' => 0, 'template' => 'page-templates/tools.php' );
$GLOBALS['posts'][2] = (object) array( 'ID' => 2, 'post_type' => 'page', 'post_name' => 'mitre-atlas-mapper', 'post_parent' => 1, 'template' => 'page-templates/tool.php' );
$GLOBALS['posts'][3] = (object) array( 'ID' => 3, 'post_type' => 'page', 'post_name' => 'mitre-atlas-mapper', 'post_parent' => 0, 'template' => 'page-templates/tool.php' );
$GLOBALS['posts'][4] = (object) array( 'ID' => 4, 'post_type' => 'page', 'post_name' => 'mcp-security-checker', 'post_parent' => 1, 'template' => 'page-templates/tool.php' );
$GLOBALS['posts'][5] = (object) array( 'ID' => 5, 'post_type' => 'page', 'post_name' => 'mitre-atlas-mapper', 'post_parent' => 1, 'template' => '' );

check( 'cyberdat_atl_render' === apply_filters( 'cyberdat/tool/renderer', null, 2 ), 'renderer registered for /tools/mitre-atlas-mapper/ with the Tool template' );
foreach ( array( 3 => 'outside the /tools/ hub', 5 => 'without the Tool template', 99 => 'for a missing post' ) as $id => $why ) { check( null === apply_filters( 'cyberdat/tool/renderer', null, $id ), "no renderer $why" ); }
check( 'cyberdat_mcp_render' === apply_filters( 'cyberdat/tool/renderer', null, 4 ), 'other tools keep their renderers' );

ob_start();
cyberdat_atl_render( 2 );
$html = ob_get_clean();
check( str_contains( $html, 'data-atl ' ) && str_contains( $html, 'atlas-mapper/worker.js?ver=123&#038;ev=123&#038;dv=123' ), 'workspace renders with the same-origin worker URL (engine and data versions)' );
foreach ( array( 'How it works', 'Privacy', 'Limitations', 'Data source and license', 'This tool does not transmit the text you enter', 'and this tool does not write it to persistent browser storage', 'This tool does not persist data', 'System profile', 'Finding mapper', 'Browse', 'CyberDat mapping', 'not an assessment by MITRE', 'not a security assessment', 'Apache License, Version 2.0', 'Copyright 2021-2026 MITRE', 'LICENSE-ATLAS.txt', 'LICENSE-APACHE-2.0.txt', 'Modified by CyberDat', 'release 2026.10', 'f56c1468731d6428e5bf875263b4643b46d67437', 'built-in page translator' ) as $needle ) {
	check( str_contains( $html, $needle ), "required text present: $needle" );
}
preg_match( '#id="cd-atl-limits".*?<li>(.*?)</li>#s', $html, $first );
check( str_starts_with( $first[1] ?? '', 'Mapping is done by rules and keywords. It misses what is described in other words or in another language' ), 'Limitations start with: rule and keyword mapping misses other wording and languages' );
check( ! preg_match( '/\b(?:compliant|certified|complete coverage)\b/i', $html ), 'no compliance, certification or coverage claims' );
preg_match_all( '#<a\b[^>]*href="([^"]+)"#', $html, $links );
check( array() === $links[1], 'no links in the tool markup (sources by name only)' );
check( ! preg_match( '/<(?:img|iframe|script|link)\b/i', $html ), 'no auto-loading resources in tool markup' );
check( ! preg_match( '/<form\b|action=|method=/i', $html ), 'no form can submit input to WordPress' );
check( ! preg_match( '/[\x{0400}-\x{04FF}]/u', $html ), 'interface text is English only' );
libxml_use_internal_errors( true );
$doc = new DOMDocument();
check( $doc->loadHTML( '<!doctype html><meta charset="utf-8">' . $html ), 'markup parses as HTML' );
$xp = new DOMXPath( $doc );
$ids = array();
foreach ( $xp->query( '//*[@id]' ) as $node ) { $ids[] = $node->getAttribute( 'id' ); }
check( count( $ids ) === count( array_unique( $ids ) ), 'element ids are unique' );
foreach ( $xp->query( '//label[@for]' ) as $label ) { check( in_array( $label->getAttribute( 'for' ), $ids, true ), 'label for="' . $label->getAttribute( 'for' ) . '" targets an element' ); }
$bad = 0;
foreach ( $xp->query( '//textarea | //input[@type="search"] | //*[@data-atl-results] | //*[@data-atl-error] | //*[@data-atl-selection] | //*[@data-atl-browse]' ) as $c ) { if ( 'no' !== $c->getAttribute( 'translate' ) || ! in_array( 'notranslate', explode( ' ', $c->getAttribute( 'class' ) ), true ) ) { $bad++; } }
check( 0 === $bad, 'finding text, search, browse view, results, selection and error box carry translate="no" and notranslate' );
$engine = file_get_contents( __DIR__ . '/../wp-content/themes/cyberdat/assets/js/atlas-mapper/engine.js' );
preg_match( "/const ENGINE = '([^']+)';\s*const RULESET = '([^']+)';/", $engine, $v );
$snap = json_decode( file_get_contents( __DIR__ . '/../deploy/tools-atlas-mapper/atlas-snapshot.json' ), true );
check( CYBERDAT_ATL_ENGINE === $v[1] && CYBERDAT_ATL_RULESET === $v[2] && CYBERDAT_ATL_DATA_RELEASE === $snap['release'] && CYBERDAT_ATL_DATA_DATE === $snap['releaseDate'] && CYBERDAT_ATL_DATA_COMMIT === $snap['commit'], 'engine, mapping and ATLAS data versions on the page match engine.js and the snapshot' );
preg_match_all( "/'([a-z-]+)': \['([^']+)'/", $engine, $props, PREG_SET_ORDER );
$engine_props = array();
foreach ( $props as $p ) { $engine_props[ $p[1] ] = $p[2]; }
check( cyberdat_atl_properties() === $engine_props, 'the eight property checkboxes equal the engine properties (keys and labels)' );

$GLOBALS['queried'] = 2;
$csp = '';
foreach ( cyberdat_tool_security_header_lines() as $h ) { if ( str_starts_with( $h, 'Content-Security-Policy: ' ) ) { $csp = substr( $h, 25 ); } }
check( str_contains( $csp, "connect-src 'none'" ) && str_contains( $csp, "default-src 'none'" ) && str_contains( $csp, "worker-src 'self'" ) && ! preg_match( '#https?:|unsafe-eval#', $csp ), 'strict CSP: no network connections, no external hosts' );
cyberdat_mcp_assets();
check( array() === $GLOBALS['enqueued'], 'other tools do not load their assets on this page' );
cyberdat_atl_assets();
check( array( 'cyberdat-tools-common', 'cyberdat-atlas-mapper', 'cyberdat-atlas-mapper' ) === array_column( $GLOBALS['enqueued'], 1 ), 'tools-common.css, own stylesheet and one deferred script' );
foreach ( $GLOBALS['enqueued'] as $asset ) { check( str_starts_with( $asset[2], 'https://staging.cyberdat.eu/wp-content/themes/cyberdat/assets/' ), 'first-party asset: ' . basename( $asset[2] ) ); }
check( 'defer' === ( $GLOBALS['enqueued'][2][3]['strategy'] ?? '' ), 'script deferred' );
$GLOBALS['queried'] = 4;
$GLOBALS['enqueued'] = array();
cyberdat_atl_assets();
check( array() === $GLOBALS['enqueued'], 'mapper assets not loaded on other tool pages' );
$functions = file_get_contents( __DIR__ . '/../wp-content/themes/cyberdat/functions.php' );
check( str_contains( $functions, "require_once __DIR__ . '/inc/tool-atlas-mapper.php';" ), 'functions.php loads the tool' );
echo "All MITRE ATLAS mapper server checks passed.\n";
