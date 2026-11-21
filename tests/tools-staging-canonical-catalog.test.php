<?php
/*
 * Staging canonical scope follows the catalogue (owner decision 2026-11-21): every page whose catalogue entry is
 * "available" gets the Rank Math canonical, no "planned" entry gets it, and the theme keeps no hand-written slug list.
 * Before: cyberdat_tools_staging_canonical() had the four 1.1 slugs written in; the installer of 1.2 had to patch
 * that list (and the catalogue statuses) on staging. Fails on that code: tools 5-10 and the utility get no canonical.
 * Run: php tests/tools-staging-canonical-catalog.test.php
 */
namespace RankMath\Frontend { class Head { public $calls = 0; public function canonical() { $this->calls++; } } }
namespace {
define( 'ABSPATH', '/fixture/' );
$slug = '';
$head = new \RankMath\Frontend\Head();
$real = json_decode( file_get_contents( __DIR__ . '/../wp-content/themes/cyberdat/inc/tools-catalog.json' ), true, 32, JSON_THROW_ON_ERROR );
$catalog = $real;
function get_queried_object_id() { return 51; }
function get_post( $id ) { global $slug; return (object) array( 'post_status' => 'publish', 'post_name' => $slug ); }
function wp_get_environment_type() { return 'staging'; }
function is_singular( $type ) { return true; }
function cyberdat_tool_ready( $id ) { return true; }
function rank_math() { global $head; return (object) array( 'head' => $head ); }
function has_action( $name, $callback ) { return false; }
function cyberdat_planned_tools() { return $GLOBALS['catalog']; }
$src = file_get_contents( __DIR__ . '/../wp-content/themes/cyberdat/inc/tools.php' );
$start = strpos( $src, 'function cyberdat_tools_staging_canonical()' );
$end = strpos( $src, "add_action( 'rank_math/head', 'cyberdat_tools_staging_canonical'", $start );
eval( substr( $src, $start, $end - $start ) );
$failed = 0; $n = 0;
function check( $ok, $label ) { global $failed, $n; $n++; echo ( $ok ? 'PASS: ' : 'FAIL: ' ) . $label . "\n"; if ( ! $ok ) { $failed++; } }
function canonical_for( $s ) { global $slug, $head; $slug = $s; $before = $head->calls; cyberdat_tools_staging_canonical(); return $head->calls - $before; }

// 1. the catalogue as shipped: tools 1-10 and the Email Header Analyzer are available, each gets exactly one canonical
check( count( $real ) === 11 && count( array_filter( $real, static fn( $t ) => 'available' === $t['status'] ) ) === 11, 'shipped catalogue: tools 1-10 and the utility are "available"' );
foreach ( $real as $tool ) { check( 1 === canonical_for( $tool['slug'] ), 'available: canonical for ' . $tool['slug'] ); }
check( 0 === canonical_for( 'other-page' ) && 0 === canonical_for( 'lolbas-analyzer' ), 'a page that is not in the catalogue gets no canonical' );

// 2. the same catalogue with some entries planned: those get none, the others keep theirs
$planned = array( 'agent-leak-inspector', 'container-hardening-audit', 'email-header-analyzer' );
$catalog = array_map( static fn( $t ) => in_array( $t['slug'], $planned, true ) ? array_merge( $t, array( 'status' => 'planned' ) ) : $t, $real );
foreach ( $catalog as $tool ) {
	$want = 'available' === $tool['status'] ? 1 : 0;
	check( $want === canonical_for( $tool['slug'] ), $tool['status'] . ': ' . ( $want ? 'canonical' : 'no canonical' ) . ' for ' . $tool['slug'] );
}
$catalog = array( array( 'slug' => 'log-anonymizer' ), 'not-an-entry', array( 'slug' => 'ai-model-bom', 'status' => 'Available' ) );
check( 0 === canonical_for( 'log-anonymizer' ) && 0 === canonical_for( 'ai-model-bom' ), 'an entry without status, or with another status value, gets no canonical' );
$catalog = array();
check( 0 === canonical_for( 'log-anonymizer' ), 'an empty or unreadable catalogue gives no canonical' );

// 3. no hand-written slug list is left in the function
$body = substr( $src, $start, $end - $start );
check( ! preg_match( "/'(?:log-anonymizer|mcp-security-checker|agent-leak-inspector|email-header-analyzer)'/", $body ), 'cyberdat_tools_staging_canonical() names no tool slug' );

echo $failed ? "\nFAIL: $failed of $n checks\n" : "\nPASS: staging canonical follows the catalogue ($n checks)\n";
exit( $failed ? 1 : 0 );
}
