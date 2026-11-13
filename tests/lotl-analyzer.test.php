<?php
/** LotL / LOLBAS Command Analyzer server contracts against narrow doubles: no WordPress, database or HTTP. */
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

function check( $ok, $label ) { if ( ! $ok ) { throw new RuntimeException( 'FAIL: ' . $label ); } echo 'PASS: ' . $label . "\n"; }

$GLOBALS['posts'][1] = (object) array( 'ID' => 1, 'post_type' => 'page', 'post_name' => 'tools', 'post_parent' => 0, 'template' => 'page-templates/tools.php' );
$GLOBALS['posts'][2] = (object) array( 'ID' => 2, 'post_type' => 'page', 'post_name' => 'lotl-command-analyzer', 'post_parent' => 1, 'template' => 'page-templates/tool.php' );
$GLOBALS['posts'][3] = (object) array( 'ID' => 3, 'post_type' => 'page', 'post_name' => 'lotl-command-analyzer', 'post_parent' => 0, 'template' => 'page-templates/tool.php' );
$GLOBALS['posts'][4] = (object) array( 'ID' => 4, 'post_type' => 'page', 'post_name' => 'lolbas-analyzer', 'post_parent' => 1, 'template' => 'page-templates/tool.php' );
$GLOBALS['posts'][5] = (object) array( 'ID' => 5, 'post_type' => 'page', 'post_name' => 'prompt-injection-detector', 'post_parent' => 1, 'template' => 'page-templates/tool.php' );
$GLOBALS['posts'][6] = (object) array( 'ID' => 6, 'post_type' => 'page', 'post_name' => 'lotl-command-analyzer', 'post_parent' => 1, 'template' => '' );

// Renderer registration ------------------------------------------------------
check( 'cyberdat_lotl_render' === apply_filters( 'cyberdat/tool/renderer', null, 2 ), 'renderer registered for /tools/lotl-command-analyzer/ with the Tool template' );
foreach ( array( 3 => 'outside the /tools/ hub', 4 => 'for the old planned slug lolbas-analyzer', 6 => 'without the Tool template', 99 => 'for a missing post' ) as $id => $why ) {
	check( null === apply_filters( 'cyberdat/tool/renderer', null, $id ), "no renderer $why" );
}
check( 'cyberdat_prompt_detector_render' === apply_filters( 'cyberdat/tool/renderer', null, 5 ), 'other tools keep their renderers' );

// Markup -----------------------------------------------------------------------
ob_start();
cyberdat_lotl_render( 2 );
$html = ob_get_clean();
$data = file_get_contents( __DIR__ . '/../wp-content/themes/cyberdat/assets/js/lotl-analyzer/lolbas-data.js', false, null, 0, 2048 );
preg_match( '/commit ([0-9a-f]{40}) \((\d{4}-\d{2}-\d{2})T/', $data, $dm );
check( str_contains( $html, 'data-lotl-analyzer' ) && str_contains( $html, 'lotl-analyzer/worker.js?ver=123&#038;ev=123&#038;dv=123' ), 'workspace renders with same-origin worker URL (engine and data versions)' );
foreach ( array( 'How it works', 'Privacy', 'Limitations of automated analysis', 'Data source and license', 'This tool does not transmit the text you enter', 'the background worker is restarted and the browser downloads its static script files again', 'A match is not a verdict.', 'Most binaries listed in LOLBAS are legitimate', 'no match does not mean the command is safe', 'GNU General Public License v3.0', 'modified version', 'License text (GPL-3.0)', 'ATT&amp;CK® is a registered trademark of The MITRE Corporation', 'This work is reproduced and distributed with the permission of The MITRE Corporation', 'No technique mapping is added by CyberDat', 'never executed' ) as $needle ) {
	check( str_contains( $html, $needle ), "required text present: $needle" );
}
check( 3 === count( $dm ) && str_contains( $html, 'Snapshot of commit ' . $dm[1] . ' from ' . $dm[2] ) && str_contains( $html, 'LOLBAS data ' . substr( $dm[1], 0, 12 ) . ' (' . $dm[2] . ')' ), 'LOLBAS data commit and date shown on the page match the bundled snapshot' );
check( str_contains( $html, 'href="https://staging.cyberdat.eu/wp-content/themes/cyberdat/assets/js/lotl-analyzer/LICENSE-LOLBAS.txt"' ), 'license text linked from the theme (same origin)' );
preg_match_all( '#<a\b[^>]*href="([^"]+)"[^>]*>#', $html, $links );
foreach ( $links[1] as $href ) {
	check( str_starts_with( $href, 'https://staging.cyberdat.eu/' ) || 'https://github.com/LOLBAS-Project/LOLBAS' === $href || str_starts_with( $href, 'https://github.com/CyberDat/CyberDat-AI/tree/feat/tools-release-1-license-claims/' ) || str_starts_with( $href, 'https://github.com/CyberDat/CyberDat-AI/raw/refs/heads/feat/tools-release-1-license-claims/' ), 'only expected links in markup: ' . $href );
}
check( ! preg_match( '/<(?:img|iframe|script|link)\b/i', $html ), 'no auto-loading resources (img, iframe, script, link) in tool markup' );
check( ! preg_match( '/<form\b|action=|method=/i', $html ), 'no form can submit input to WordPress' );
check( ! preg_match( '/gtfobins/i', $html ), 'GTFOBins is not used' );
check( ! preg_match( '/[\x{0400}-\x{04FF}]/u', $html ), 'interface text is English only' );
check( str_contains( $html, 'spellcheck="false"' ) && str_contains( $html, 'role="status"' ) && str_contains( $html, 'role="alert"' ), 'input opts out of spellcheck; live regions present' );
libxml_use_internal_errors( true );
$doc = new DOMDocument();
check( $doc->loadHTML( '<!doctype html><meta charset="utf-8">' . $html ), 'markup parses as HTML' );
$xp = new DOMXPath( $doc );
$ids = array();
foreach ( $xp->query( '//*[@id]' ) as $node ) { $ids[] = $node->getAttribute( 'id' ); }
check( count( $ids ) === count( array_unique( $ids ) ), 'element ids are unique' );
foreach ( $xp->query( '//label[@for]' ) as $label ) { check( in_array( $label->getAttribute( 'for' ), $ids, true ), 'label for="' . $label->getAttribute( 'for' ) . '" targets an element' ); }

// Versions -------------------------------------------------------------------------
$engine = file_get_contents( __DIR__ . '/../wp-content/themes/cyberdat/assets/js/lotl-analyzer/engine.js' );
preg_match( "/const VERSION = '([^']+)';\s*const RULESET_VERSION = '([^']+)';/", $engine, $v );
check( CYBERDAT_LOTL_ENGINE === $v[1] && CYBERDAT_LOTL_RULESET === $v[2] && str_contains( $html, 'Engine ' . $v[1] . ' · heuristics ' . $v[2] ), 'engine and heuristics versions shown on the page match engine.js' );

// Security headers and assets ------------------------------------------------------
$GLOBALS['queried'] = 2;
$csp = '';
foreach ( cyberdat_tool_security_header_lines() as $h ) { if ( str_starts_with( $h, 'Content-Security-Policy: ' ) ) { $csp = substr( $h, 25 ); } }
check( str_contains( $csp, "connect-src 'none'" ) && str_contains( $csp, "default-src 'none'" ) && str_contains( $csp, "worker-src 'self'" ) && ! preg_match( '#https?:|unsafe-eval#', $csp ), 'strict CSP on the analyzer page: no network connections, no external hosts' );
cyberdat_prompt_detector_assets();
cyberdat_log_anonymizer_assets();
check( array() === $GLOBALS['enqueued'], 'other tools do not load their assets on this page' );
cyberdat_lotl_assets();
check( array( 'cyberdat-tools-common', 'cyberdat-lotl-analyzer', 'cyberdat-lotl-analyzer' ) === array_column( $GLOBALS['enqueued'], 1 ), 'tools-common.css, own stylesheet and one deferred script' );
foreach ( $GLOBALS['enqueued'] as $asset ) { check( str_starts_with( $asset[2], 'https://staging.cyberdat.eu/wp-content/themes/cyberdat/assets/' ), 'asset is a first-party theme file: ' . basename( $asset[2] ) ); }
$GLOBALS['queried'] = 5;
$GLOBALS['enqueued'] = array();
cyberdat_lotl_assets();
check( array() === $GLOBALS['enqueued'], 'analyzer assets not loaded on other tool pages' );

// Catalogue ------------------------------------------------------------------------
$catalog = json_decode( file_get_contents( __DIR__ . '/../wp-content/themes/cyberdat/inc/tools-catalog.json' ), true );
check( 'lotl-command-analyzer' === $catalog[2]['slug'] && '/tools/lotl-command-analyzer/' === $catalog[2]['url'] && 'available' === $catalog[2]['status'] && '1.1' === $catalog[2]['release'] && 'LotL / LOLBAS Command Analyzer' === $catalog[2]['title'], 'catalogue: tool 3 of release 1.1 points to /tools/lotl-command-analyzer/, name unchanged' );
echo "All LotL Command Analyzer server checks passed.\n";
