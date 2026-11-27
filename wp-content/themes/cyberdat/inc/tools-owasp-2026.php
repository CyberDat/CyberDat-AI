<?php
/**
 * OWASP 2026 references of the AI tools (page text only; no rule, engine or export changes).
 * IDs and titles are copied from the official sources listed in docs/OWASP-2026-MAPPING.md:
 * OWASP Top 10 for LLM Applications 2026 (GenAI-Security-Project/GenAI-LLM-Top10, 2026/final, released 2026-08-04,
 * CC BY-SA 4.0) and OWASP Top 10 for Agentic Applications 2026 (published 2025-12-09).
 * Tool pages name their sources without links (accepted rule of the tool pages, checked by their tests); the URLs
 * are in docs/OWASP-2026-MAPPING.md. The per-tool mapping is CyberDat's tool-level mapping, not a claim of coverage.
 */
defined( 'ABSPATH' ) || exit;

/** OWASP Top 10 for LLM Applications 2026: ID => title. */
const CYBERDAT_OWASP_LLM_2026 = array(
	'LLM01:2026' => 'Prompt Injection',
	'LLM02:2026' => 'Sensitive Information Disclosure',
	'LLM03:2026' => 'Excessive Agency',
	'LLM04:2026' => 'Supply Chain',
	'LLM05:2026' => 'Data and Model Poisoning',
	'LLM06:2026' => 'Unbounded Consumption',
	'LLM07:2026' => 'Misinformation',
	'LLM08:2026' => 'Hidden Context Exposure',
	'LLM09:2026' => 'Vector and Embedding Weaknesses',
	'LLM10:2026' => 'Improper Output Handling',
);

/** OWASP Top 10 for Agentic Applications 2026: ID => title. */
const CYBERDAT_OWASP_ASI_2026 = array(
	'ASI01' => 'Agent Goal Hijack',
	'ASI02' => 'Tool Misuse & Exploitation',
	'ASI03' => 'Identity & Privilege Abuse',
	'ASI04' => 'Agentic Supply Chain Vulnerabilities',
	'ASI05' => 'Unexpected Code Execution (RCE)',
	'ASI06' => 'Memory & Context Poisoning',
	'ASI07' => 'Insecure Inter-Agent Communication',
	'ASI08' => 'Cascading Failures',
	'ASI09' => 'Human-Agent Trust Exploitation',
	'ASI10' => 'Rogue Agents',
);

/** Tool page slug => [LLM 2026 IDs, related Agentic 2026 IDs]. Rationale per tool: docs/OWASP-2026-MAPPING.md. */
const CYBERDAT_TOOLS_OWASP_2026 = array(
	'prompt-injection-detector'   => array( array( 'LLM01:2026' ), array( 'ASI01' ) ),
	'prompt-injection-test-bench' => array( array( 'LLM01:2026' ), array( 'ASI01' ) ),
	'agent-leak-inspector'        => array( array( 'LLM08:2026', 'LLM02:2026', 'LLM03:2026' ), array( 'ASI01', 'ASI02' ) ),
	'mcp-security-checker'        => array( array( 'LLM03:2026', 'LLM04:2026' ), array( 'ASI02', 'ASI03', 'ASI04' ) ),
	'ai-model-bom'                => array( array( 'LLM04:2026' ), array() ),
);

if ( ! function_exists( 'cyberdat_rules_updated' ) ) {
	/** The update date of a ruleset identifier "YYYY-MM-DD.N" ("" when it has none). */
	function cyberdat_rules_updated( $ruleset ) {
		return preg_match( '/^(\d{4}-\d{2}-\d{2})\b/', (string) $ruleset, $m ) ? $m[1] : '';
	}

	/** The "Mapped to OWASP …" line under a tool's version line (names only, no links). */
	function cyberdat_tools_owasp_line( $slug ) {
		if ( 'mitre-atlas-mapper' === $slug ) {
			return '<p class="cd-la-meta" data-owasp-2026>' . esc_html__( 'Maps to MITRE ATLAS, not to OWASP. The OWASP Top 10 for LLM Applications 2026 publishes its own crosswalk to MITRE ATLAS in its Appendix A.', 'cyberdat' ) . '</p>';
		}
		if ( ! isset( CYBERDAT_TOOLS_OWASP_2026[ $slug ] ) ) {
			return '';
		}
		list( $llm, $asi ) = CYBERDAT_TOOLS_OWASP_2026[ $slug ];
		$name = static function ( $id, $title ) { return $id . ' ' . $title; };
		$text = 'Mapped to OWASP Top 10 for LLM Applications 2026: ' . implode( ', ', array_map( static function ( $id ) use ( $name ) { return $name( $id, CYBERDAT_OWASP_LLM_2026[ $id ] ); }, $llm ) ) . '.';
		if ( $asi ) {
			$text .= ' Related: OWASP Top 10 for Agentic Applications 2026, ' . implode( ', ', array_map( static function ( $id ) use ( $name ) { return $name( $id, CYBERDAT_OWASP_ASI_2026[ $id ] ); }, $asi ) ) . '.';
		}
		$text .= ' CyberDat’s tool-level mapping, referenced by name only; it does not mean that every risk of an entry is detected.';
		return '<p class="cd-la-meta" data-owasp-2026>' . esc_html( $text ) . '</p>';
	}
}
