<?php
/** Prompt Injection Detector server contracts against narrow doubles: no WordPress, database or HTTP. */
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
require __DIR__ . '/../wp-content/themes/cyberdat/inc/tool-prompt-injection-detector.php';

function check( $ok, $label ) { if ( ! $ok ) { throw new RuntimeException( 'FAIL: ' . $label ); } echo 'PASS: ' . $label . "\n"; }

$GLOBALS['posts'][1] = (object) array( 'ID' => 1, 'post_type' => 'page', 'post_name' => 'tools', 'post_parent' => 0, 'template' => 'page-templates/tools.php' );
$GLOBALS['posts'][2] = (object) array( 'ID' => 2, 'post_type' => 'page', 'post_name' => 'prompt-injection-detector', 'post_parent' => 1, 'template' => 'page-templates/tool.php' );
$GLOBALS['posts'][3] = (object) array( 'ID' => 3, 'post_type' => 'page', 'post_name' => 'prompt-injection-detector', 'post_parent' => 0, 'template' => 'page-templates/tool.php' );
$GLOBALS['posts'][4] = (object) array( 'ID' => 4, 'post_type' => 'page', 'post_name' => 'prompt-injection-detector', 'post_parent' => 1, 'template' => '' );
$GLOBALS['posts'][5] = (object) array( 'ID' => 5, 'post_type' => 'page', 'post_name' => 'log-anonymizer', 'post_parent' => 1, 'template' => 'page-templates/tool.php' );
$GLOBALS['posts'][6] = (object) array( 'ID' => 6, 'post_type' => 'post', 'post_name' => 'prompt-injection-detector', 'post_parent' => 1, 'template' => 'page-templates/tool.php' );
$GLOBALS['posts'][7] = (object) array( 'ID' => 7, 'post_type' => 'page', 'post_name' => 'prompt-sanitizer', 'post_parent' => 1, 'template' => 'page-templates/tool.php' );

// Renderer registration ------------------------------------------------------
check( 'cyberdat_prompt_detector_render' === apply_filters( 'cyberdat/tool/renderer', null, 2 ), 'renderer registered for /tools/prompt-injection-detector/ with the Tool template' );
foreach ( array( 3 => 'outside the /tools/ hub', 4 => 'without the Tool template', 6 => 'for a post with the same slug', 7 => 'for the old planned slug prompt-sanitizer', 99 => 'for a missing post' ) as $id => $why ) {
	check( null === apply_filters( 'cyberdat/tool/renderer', null, $id ), "no renderer $why" );
}
check( 'cyberdat_log_anonymizer_render' === apply_filters( 'cyberdat/tool/renderer', null, 5 ), 'Log Anonymizer keeps its own renderer (filters do not interfere)' );

// Markup -----------------------------------------------------------------------
ob_start();
cyberdat_prompt_detector_render( 2 );
$html = ob_get_clean();
check( str_contains( $html, 'data-prompt-detector' ) && str_contains( $html, 'data-worker-src="https://staging.cyberdat.eu/wp-content/themes/cyberdat/assets/js/prompt-injection-detector/worker.js?ver=123&#038;ev=123"' ), 'workspace renders with same-origin worker URL' );
$required = array( 'How it works', 'Privacy', 'Limitations of automated analysis', 'This tool does not transmit the text you enter', 'the background worker is restarted and the browser downloads its two static script files again', 'Automated analysis cannot detect every prompt injection', 'No guarantee of safety.', 'Still untrusted.', 'Changes: before and after', 'Engine 1.0.1 · rules 2026-11-11.1' );
foreach ( $required as $needle ) {
	check( str_contains( $html, $needle ), "required text present: $needle" );
}
$plain = strip_tags( str_replace( 'No guarantee of safety.', '', $html ) );
check( ! preg_match( '/\b(?:guarantees? (?:that|your|complete|full)|100\s?%|fully (?:safe|secure|protected)|completely safe|blocks all|catches all|detects all)\b/i', $plain ), 'no promise of complete safety anywhere in the interface' );
$engine = file_get_contents( __DIR__ . '/../wp-content/themes/cyberdat/assets/js/prompt-injection-detector/engine.js' );
preg_match_all( "/\{ id: '([a-z]+)', name: '/", $engine, $engine_groups );
check( array_keys( cyberdat_prompt_detector_groups() ) === $engine_groups[1] && 7 === count( $engine_groups[1] ), 'the seven rule groups match the engine, in order' );
preg_match( "/const VERSION = '([^']+)';\s*const RULESET_VERSION = '([^']+)';/", $engine, $versions );
check( CYBERDAT_PROMPT_DETECTOR_ENGINE === $versions[1] && CYBERDAT_PROMPT_DETECTOR_RULESET === $versions[2], 'engine and ruleset versions shown on the page match engine.js' );
check( ! preg_match( '/<form\b|action=|method=/i', $html ), 'no form can submit input to WordPress' );
check( ! preg_match( '#(src|href)=["\']https?://(?!staging\.cyberdat\.eu/)#i', $html ), 'no third-party resource URLs in markup' );
check( ! preg_match( '/<script\b/i', $html ), 'no inline script in tool markup' );
check( str_contains( $html, 'spellcheck="false"' ) && str_contains( $html, 'data-gramm="false"' ) && str_contains( $html, 'autocomplete="off"' ), 'input field opts out of cloud spellcheck, grammar extensions and autofill' );
check( str_contains( $html, 'role="status"' ) && str_contains( $html, 'role="alert"' ) && str_contains( $html, 'aria-live="polite"' ), 'live regions for status and errors' );
check( ! preg_match( '/[\x{0400}-\x{04FF}]/u', $html ), 'interface text is English only' );
libxml_use_internal_errors( true );
$doc = new DOMDocument();
check( $doc->loadHTML( '<!doctype html><meta charset="utf-8">' . $html ), 'markup parses as HTML' );
$xp = new DOMXPath( $doc );
$ids = array();
foreach ( $xp->query( '//*[@id]' ) as $node ) { $ids[] = $node->getAttribute( 'id' ); }
check( count( $ids ) === count( array_unique( $ids ) ), 'element ids are unique' );
foreach ( $xp->query( '//label[@for]' ) as $label ) {
	check( in_array( $label->getAttribute( 'for' ), $ids, true ), 'label for="' . $label->getAttribute( 'for' ) . '" targets an element' );
}
$wrapped = 0;
$boxes = $xp->query( '//input[@type="checkbox" or @type="radio"]' );
foreach ( $boxes as $box ) { $wrapped += 'label' === $box->parentNode->nodeName ? 1 : 0; }
check( $boxes->length === $wrapped && $boxes->length >= 6, 'every option (' . $boxes->length . ') is wrapped in its label' );

// Security headers apply to this tool page too -------------------------------
$GLOBALS['queried'] = 2;
$csp = '';
foreach ( cyberdat_tool_security_header_lines() as $h ) { if ( str_starts_with( $h, 'Content-Security-Policy: ' ) ) { $csp = substr( $h, 25 ); } }
check( str_contains( $csp, "connect-src 'none'" ) && str_contains( $csp, "default-src 'none'" ) && str_contains( $csp, "worker-src 'self'" ) && ! str_contains( $csp, 'unsafe-eval' ), 'strict CSP (connect-src none, worker self, no unsafe-eval) on the detector page' );

// Assets -------------------------------------------------------------------------
$GLOBALS['queried'] = 5;
cyberdat_prompt_detector_assets();
check( array() === $GLOBALS['enqueued'], 'detector assets not loaded on the Log Anonymizer page' );
$GLOBALS['queried'] = 2;
cyberdat_log_anonymizer_assets();
check( array() === $GLOBALS['enqueued'], 'Log Anonymizer script and styles are not loaded under their own handles on the detector page' );
cyberdat_prompt_detector_assets();
$handles = array_column( $GLOBALS['enqueued'], 1 );
check( array( 'cyberdat-tools-common', 'cyberdat-prompt-detector', 'cyberdat-prompt-detector' ) === $handles, 'shared tools-common stylesheet, own stylesheet and one deferred script' );
check( str_ends_with( $GLOBALS['enqueued'][0][2], '/assets/css/tools-common.css' ) && array( 'cyberdat-tools-common' ) === $GLOBALS['enqueued'][1][3], 'detector stylesheet builds on the shared tools-common.css (not on log-anonymizer.css)' );
foreach ( $GLOBALS['enqueued'] as $asset ) { check( str_starts_with( $asset[2], 'https://staging.cyberdat.eu/wp-content/themes/cyberdat/assets/' ), 'asset is a first-party theme file: ' . basename( $asset[2] ) ); }
check( 'defer' === $GLOBALS['enqueued'][2][3]['strategy'], 'script deferred' );

// Catalogue ------------------------------------------------------------------------
$catalog = json_decode( file_get_contents( __DIR__ . '/../wp-content/themes/cyberdat/inc/tools-catalog.json' ), true );
$entry = $catalog[1];
check( 'prompt-injection-detector' === $entry['slug'] && '/tools/prompt-injection-detector/' === $entry['url'] && 'available' === $entry['status'] && '1.1' === $entry['release'], 'catalogue: tool 2 of release 1.1 points to /tools/prompt-injection-detector/' );
check( 'Indirect Prompt Injection Sanitizer & Detector' === $entry['title'], 'catalogue: tool name unchanged' );
echo "All Prompt Injection Detector server checks passed.\n";
