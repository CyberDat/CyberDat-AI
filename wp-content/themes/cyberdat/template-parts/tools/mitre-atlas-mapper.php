<?php
/**
 * MITRE ATLAS Attack Vector Mapper — interactive workspace markup.
 * Static, server-rendered UI only. Profiles, pasted findings and notes are processed in the browser by
 * assets/js/atlas-mapper/*.js; nothing is posted to WordPress and no model, MITRE site or other service is contacted.
 * Inputs, notes and results carry translate="no" and the notranslate class so that a built-in page translator does
 * not send the entered text to a translation service. Shared .cd-la-* classes come from assets/css/tools-common.css.
 */
defined( 'ABSPATH' ) || exit;
$cyberdat_atl = cyberdat_atl_config();
$cyberdat_atl_props = cyberdat_atl_properties();
$cyberdat_atl_ta = 'class="cd-la-input notranslate" translate="no" spellcheck="false" autocomplete="off" autocapitalize="off" autocorrect="off" data-gramm="false" data-gramm_editor="false" data-enable-grammarly="false" data-lt-active="false"';
?>
<div class="cd-la cd-atl" data-atl data-worker-src="<?php echo esc_url( $cyberdat_atl['worker'] ); ?>">
	<noscript><p class="cd-la-callout cd-la-callout--warning"><?php esc_html_e( 'This tool needs JavaScript. Everything happens only in your browser, so nothing can run without it — and nothing is uploaded.', 'cyberdat' ); ?></p></noscript>
	<p class="cd-la-callout cd-la-callout--error" data-atl-unsupported hidden><?php esc_html_e( 'Your browser does not support the background processing this tool needs (Web Workers). Try a current version of Edge, Chrome, Firefox or Safari.', 'cyberdat' ); ?></p>

	<div class="cd-la-app" data-atl-app hidden>
		<p class="cd-la-callout cd-la-callout--privacy"><strong><?php esc_html_e( 'Local only.', 'cyberdat' ); ?></strong> <?php esc_html_e( 'Your text is analyzed in this browser tab. This tool does not transmit the text you enter — not to CyberDat, not to analytics, not to any AI service — and this tool does not write it to persistent browser storage.', 'cyberdat' ); ?></p>
		<p class="cd-la-callout cd-la-callout--warning" role="note"><strong><?php esc_html_e( 'Candidates for review, not an assessment.', 'cyberdat' ); ?></strong> <?php esc_html_e( 'Techniques are proposed by CyberDat mapping rules and keywords. The result is a starting point for analysis, not a security assessment and not a complete threat model. Technique names, ids, tactics and mitigations are MITRE ATLAS data; why a technique is proposed is CyberDat mapping, not an assessment by MITRE.', 'cyberdat' ); ?></p>

		<fieldset class="cd-atl-modes">
			<legend class="cd-la-label"><?php esc_html_e( 'What do you want to do?', 'cyberdat' ); ?></legend>
			<label class="cd-atl-mode"><input type="radio" name="cd-atl-mode" value="profile" checked data-atl-mode> <span><strong><?php esc_html_e( 'System profile', 'cyberdat' ); ?></strong> — <?php esc_html_e( 'describe your AI system and see which techniques apply', 'cyberdat' ); ?></span></label>
			<label class="cd-atl-mode"><input type="radio" name="cd-atl-mode" value="finding" data-atl-mode> <span><strong><?php esc_html_e( 'Finding mapper', 'cyberdat' ); ?></strong> — <?php esc_html_e( 'paste a description of a finding or incident and get candidate techniques', 'cyberdat' ); ?></span></label>
			<label class="cd-atl-mode"><input type="radio" name="cd-atl-mode" value="browse" data-atl-mode> <span><strong><?php esc_html_e( 'Browse', 'cyberdat' ); ?></strong> — <?php esc_html_e( 'search tactics, techniques and mitigations by id or name', 'cyberdat' ); ?></span></label>
		</fieldset>

		<section class="cd-la-panel" aria-labelledby="cd-atl-step-profile" data-atl-panel="profile">
			<h2 id="cd-atl-step-profile" class="cd-la-step"><span aria-hidden="true">1</span> <?php esc_html_e( 'Describe the system', 'cyberdat' ); ?></h2>
			<fieldset class="cd-la-fieldset">
				<legend><?php esc_html_e( 'Select every property that applies', 'cyberdat' ); ?></legend>
				<div class="cd-la-checks">
					<?php foreach ( $cyberdat_atl_props as $cyberdat_key => $cyberdat_label ) : ?>
						<label class="cd-la-check"><input type="checkbox" value="<?php echo esc_attr( $cyberdat_key ); ?>" data-atl-property> <span><?php echo esc_html( $cyberdat_label ); ?></span></label>
					<?php endforeach; ?>
				</div>
			</fieldset>
		</section>

		<section class="cd-la-panel" aria-labelledby="cd-atl-step-finding" data-atl-panel="finding" hidden>
			<h2 id="cd-atl-step-finding" class="cd-la-step"><span aria-hidden="true">1</span> <?php esc_html_e( 'Describe the finding', 'cyberdat' ); ?></h2>
			<label class="cd-la-label" for="cd-atl-text"><?php esc_html_e( 'Finding or incident description', 'cyberdat' ); ?></label>
			<textarea id="cd-atl-text" <?php echo $cyberdat_atl_ta; // phpcs:ignore WordPress.Security.EscapeOutput -- static attribute string ?> rows="10" maxlength="100000" aria-describedby="cd-atl-text-help" data-atl-text></textarea>
			<p id="cd-atl-text-help" class="cd-la-help"><?php esc_html_e( 'Plain text in English, German or Russian, up to 100,000 characters. Describe what happened in your own words. Remove secrets first; values that look like secrets are masked in the results and are never exported.', 'cyberdat' ); ?></p>
			<div class="cd-la-row">
				<button type="button" class="cd-la-button cd-la-button--secondary" data-atl-sample><?php esc_html_e( 'Load example', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--ghost" data-atl-clear-text><?php esc_html_e( 'Clear', 'cyberdat' ); ?></button>
			</div>
		</section>

		<section class="cd-la-panel" aria-labelledby="cd-atl-step-browse" data-atl-panel="browse" hidden>
			<h2 id="cd-atl-step-browse" class="cd-la-step"><span aria-hidden="true">1</span> <?php esc_html_e( 'Search MITRE ATLAS', 'cyberdat' ); ?></h2>
			<label class="cd-la-label" for="cd-atl-search"><?php esc_html_e( 'Id or name', 'cyberdat' ); ?></label>
			<input id="cd-atl-search" type="search" class="cd-la-text cd-atl-search notranslate" translate="no" spellcheck="false" autocomplete="off" maxlength="200" aria-describedby="cd-atl-search-help" data-atl-search>
			<p id="cd-atl-search-help" class="cd-la-help"><?php esc_html_e( 'For example AML.T0051, “prompt injection” or “guardrails”. Leave empty to list the tactics.', 'cyberdat' ); ?></p>
			<div class="cd-atl-browse notranslate" translate="no" aria-live="polite" data-atl-browse></div>
		</section>

		<div class="cd-la-actions" data-atl-actions>
			<button type="button" class="cd-la-button cd-la-button--primary" data-atl-run><?php esc_html_e( 'Show techniques', 'cyberdat' ); ?></button>
			<button type="button" class="cd-la-button cd-la-button--ghost" data-atl-cancel hidden><?php esc_html_e( 'Cancel', 'cyberdat' ); ?></button>
			<progress class="cd-la-progress" max="100" value="0" aria-label="<?php esc_attr_e( 'Progress', 'cyberdat' ); ?>" data-atl-progress hidden></progress>
		</div>
		<p class="cd-la-status" role="status" aria-live="polite" data-atl-status></p>
		<div class="cd-la-callout cd-la-callout--error notranslate" translate="no" role="alert" data-atl-error hidden></div>

		<section class="cd-la-panel cd-la-results notranslate" translate="no" aria-labelledby="cd-atl-step-results" data-atl-results hidden>
			<h2 id="cd-atl-step-results" class="cd-la-step" tabindex="-1"><span aria-hidden="true">2</span> <b class="cd-atl-step-title"><?php esc_html_e( 'Review the candidates', 'cyberdat' ); ?></b></h2>
			<p class="cd-atl-verdict" data-atl-verdict></p>
			<p class="cd-la-summary" data-atl-summary></p>
			<ul class="cd-atl-notes" data-atl-notes hidden></ul>
			<div data-atl-groups></div>
		</section>

		<section class="cd-la-panel notranslate" translate="no" aria-labelledby="cd-atl-selection-title" data-atl-selection>
			<h2 id="cd-atl-selection-title" class="cd-la-step" tabindex="-1"><span aria-hidden="true">3</span> <b class="cd-atl-step-title"><?php esc_html_e( 'Your selection', 'cyberdat' ); ?></b></h2>
			<p class="cd-la-help" data-atl-selection-empty><?php esc_html_e( 'Nothing selected yet. Use “Add to selection” on a technique.', 'cyberdat' ); ?></p>
			<ol class="cd-atl-selected" data-atl-selected></ol>
			<div class="cd-la-row">
				<button type="button" class="cd-la-button cd-la-button--secondary" data-atl-export="markdown" disabled><?php esc_html_e( 'Download Markdown', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--secondary" data-atl-export="json" disabled><?php esc_html_e( 'Download JSON', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--ghost" data-atl-clear-selection disabled><?php esc_html_e( 'Clear selection', 'cyberdat' ); ?></button>
			</div>
			<p class="cd-la-help"><?php esc_html_e( 'The export contains the selected techniques, their ids, tactics and related mitigations, your notes (values that look like secrets are masked) and the ATLAS data version. It does not contain the pasted finding text.', 'cyberdat' ); ?></p>
		</section>
	</div>

	<div class="cd-la-info">
		<section aria-labelledby="cd-atl-how">
			<h2 id="cd-atl-how"><?php esc_html_e( 'How it works', 'cyberdat' ); ?></h2>
			<ol>
				<li><?php esc_html_e( 'System profile: each property you select is linked to MITRE ATLAS techniques by CyberDat mapping rules, each with a short reason. The techniques are grouped by ATLAS tactic and shown with the mitigations that ATLAS links to them.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Finding mapper: CyberDat keyword rules in English, German and Russian look for words that describe a technique, such as “indirect prompt injection” or “pickle file”. Each candidate shows the words that led to it. No AI model is used.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Browse: search the bundled ATLAS data by id or name and open tactics, techniques, sub-techniques and mitigations.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Add techniques to your selection, write notes and download the selection as Markdown or JSON.', 'cyberdat' ); ?></li>
			</ol>
			<?php require_once dirname( __DIR__, 2 ) . '/inc/tools-owasp-2026.php'; ?>
			<p class="cd-la-meta"><?php printf( esc_html__( 'Engine %1$s · CyberDat mapping %2$s · MITRE ATLAS %3$s · mapping updated %4$s', 'cyberdat' ), esc_html( $cyberdat_atl['engine_version'] ), esc_html( $cyberdat_atl['ruleset'] ), esc_html( $cyberdat_atl['data_release'] ), esc_html( cyberdat_rules_updated( $cyberdat_atl['ruleset'] ) ) ); ?></p>
			<?php echo cyberdat_tools_owasp_line( 'mitre-atlas-mapper' ); // phpcs:ignore WordPress.Security.EscapeOutput -- escaped in the helper ?>
		</section>
		<section aria-labelledby="cd-atl-privacy">
			<h2 id="cd-atl-privacy"><?php esc_html_e( 'Privacy', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'This tool does not transmit the text you enter. The page has no server endpoint for your data, it does not call any AI model or external service, and its Content Security Policy blocks scripts on this page from opening network connections. The ATLAS data is part of this page, so the MITRE website is not contacted.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Input fields, notes and results are marked so that the browser’s built-in page translator does not translate them, because translating would send their text to a translation service.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'If you select Cancel (or processing times out), the background worker is restarted and the browser downloads its static script files again from this site. Those requests contain no part of your input.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'This tool does not persist data: input, findings and settings are not written to cookies, local storage or the address bar, and the tool resets them when you close or reload the tab. Browser session restore, extensions, the clipboard and downloaded files are outside these controls; this is not secure erasure.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Values in the pasted text that look like secrets are shown only as their type and a masked fragment; masking is best effort.', 'cyberdat' ); ?></li>
			</ul>
		</section>
		<section aria-labelledby="cd-atl-limits">
			<h2 id="cd-atl-limits"><?php esc_html_e( 'Limitations', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'Mapping is done by rules and keywords. It misses what is described in other words or in another language, and it can propose a technique because a word appears in an unrelated sense.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'A word that its own clause denies, such as “there was no prompt injection”, “the bot refused to reveal its prompt” or the same in German or Russian, does not lead to a technique. Only simple negations close to the word are recognized: a denial far away in a long sentence, double negations or lists like “no A, B or C” can still be read wrongly, so check every candidate.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Ordinary, permitted use of an agent tool, a reference to a secret store and routine clean-up are not mapped to attack techniques unless the text also shows abuse, for example an attacker, a malicious tool or credentials that others can read. A general description of a poisoned tool or context gets the parent technique; a sub-technique needs its specific mechanism. Because the analysis is lexical, protective or unusual wording can still produce a candidate, and an incident told in other words can be missed.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'The result is a list of candidates for review. It is not a security assessment, not a complete threat model and not a statement about coverage of MITRE ATLAS.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'System-profile rules cover eight common properties. Techniques that depend on details not captured by these properties are not proposed.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'The ATLAS data is a snapshot of one release and is not updated automatically. Mitigations shown “via” a parent technique are linked by ATLAS to the parent, not to the sub-technique.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Case studies, entities and software from ATLAS are not included in this version.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Finding texts up to 100,000 characters. Processing stops after 60 seconds.', 'cyberdat' ); ?></li>
			</ul>
		</section>
		<section aria-labelledby="cd-atl-data">
			<h2 id="cd-atl-data"><?php esc_html_e( 'Data source and license', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php printf( esc_html__( 'MITRE ATLAS™ (Adversarial Threat Landscape for AI Systems), release %1$s of %2$s, from the MITRE ATLAS data repository (mitre-atlas/atlas-data), commit %3$s.', 'cyberdat' ), esc_html( $cyberdat_atl['data_release'] ), esc_html( $cyberdat_atl['data_date'] ), esc_html( $cyberdat_atl['data_commit'] ) ); ?></li>
				<li><?php esc_html_e( 'Copyright 2021-2026 MITRE. Licensed under the Apache License, Version 2.0. The upstream license notice and the full license text are published with this tool as LICENSE-ATLAS.txt and LICENSE-APACHE-2.0.txt next to the ATLAS data file.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Modified by CyberDat: converted from YAML; only tactics, techniques, sub-techniques, mitigations and their relationships are included; links in descriptions are shown as plain text. No ids or relationships were added.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'The rules that link system properties and words to techniques are CyberDat mapping. They are not part of MITRE ATLAS and are not endorsed by MITRE. MITRE ATLAS is a trademark of The MITRE Corporation; its use here does not imply endorsement.', 'cyberdat' ); ?></li>
			</ul>
		</section>
	</div>
</div>
