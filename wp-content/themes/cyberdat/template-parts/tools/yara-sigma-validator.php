<?php
/**
 * YARA/Sigma Rule Validator & Converter — interactive workspace markup.
 * Static, server-rendered UI only. Rules are checked and converted in the browser by assets/js/yara-sigma-validator/*.js;
 * they are never compiled by YARA, never run against files and never posted to WordPress.
 * Inputs, findings and converted queries carry translate="no" and the notranslate class.
 */
defined( 'ABSPATH' ) || exit;
$cyberdat_ysv = cyberdat_ysv_config();
$cyberdat_ysv_ta = 'class="cd-la-input notranslate" translate="no" spellcheck="false" autocomplete="off" autocapitalize="off" autocorrect="off" data-gramm="false" data-gramm_editor="false" data-enable-grammarly="false" data-lt-active="false"';
?>
<div class="cd-la cd-ysv" data-ysv data-worker-state="loading" data-worker-src="<?php echo esc_url( $cyberdat_ysv['worker'] ); ?>">
	<noscript><p class="cd-la-callout cd-la-callout--warning"><?php esc_html_e( 'This tool needs JavaScript. Everything happens only in your browser, so nothing can run without it — and nothing is uploaded.', 'cyberdat' ); ?></p></noscript>
	<p class="cd-la-callout cd-la-callout--error" data-ysv-unsupported hidden><?php esc_html_e( 'Your browser does not support the background processing this tool needs (Web Workers). Try a current version of Edge, Chrome, Firefox or Safari.', 'cyberdat' ); ?></p>

	<div class="cd-la-app" data-ysv-app hidden>
		<p class="cd-la-callout cd-la-callout--privacy"><strong><?php esc_html_e( 'Local only.', 'cyberdat' ); ?></strong> <?php esc_html_e( 'Your text is analyzed in this browser tab. This tool does not transmit the text you enter — not to CyberDat, not to analytics, not to any SIEM or rule service — and this tool does not write it to persistent browser storage.', 'cyberdat' ); ?></p>
		<p class="cd-la-callout cd-la-callout--warning" role="note"><strong><?php esc_html_e( 'Static checks only.', 'cyberdat' ); ?></strong> <?php esc_html_e( 'Rules are not compiled by the YARA engine and are not run against files. Check every converted query in your own SIEM before you rely on it.', 'cyberdat' ); ?></p>
		<p class="cd-ysv-state" role="status" aria-live="polite" data-ysv-worker-status><?php esc_html_e( 'Starting the local rule checker…', 'cyberdat' ); ?></p>

		<section class="cd-la-panel" aria-labelledby="cd-ysv-step-input">
			<h2 id="cd-ysv-step-input" class="cd-la-step"><span aria-hidden="true">1</span> <?php esc_html_e( 'Add a rule', 'cyberdat' ); ?></h2>
			<label class="cd-la-label" for="cd-ysv-input"><?php esc_html_e( 'Sigma rule (YAML) or YARA rule', 'cyberdat' ); ?></label>
			<textarea id="cd-ysv-input" <?php echo $cyberdat_ysv_ta; // phpcs:ignore WordPress.Security.EscapeOutput -- static attribute string ?> rows="16" aria-describedby="cd-ysv-input-help cd-ysv-size" data-ysv-input></textarea>
			<p id="cd-ysv-input-help" class="cd-la-help"><?php esc_html_e( 'One or more Sigma rules (separate several with ---) or one YARA file with any number of rules. Up to 1 MB. Rules may contain internal host names and indicators; they stay in this tab.', 'cyberdat' ); ?></p>
			<p id="cd-ysv-size" class="cd-la-source" aria-live="polite" data-ysv-size></p>
			<fieldset class="cd-ysv-kinds">
				<legend class="cd-la-label"><?php esc_html_e( 'Rule format', 'cyberdat' ); ?></legend>
				<label class="cd-ysv-kind"><input type="radio" name="cd-ysv-kind" value="auto" checked data-ysv-kind> <span><?php esc_html_e( 'Detect automatically', 'cyberdat' ); ?></span></label>
				<label class="cd-ysv-kind"><input type="radio" name="cd-ysv-kind" value="sigma" data-ysv-kind> <span><?php esc_html_e( 'Sigma', 'cyberdat' ); ?></span></label>
				<label class="cd-ysv-kind"><input type="radio" name="cd-ysv-kind" value="yara" data-ysv-kind> <span><?php esc_html_e( 'YARA', 'cyberdat' ); ?></span></label>
			</fieldset>
			<div class="cd-la-row">
				<button type="button" class="cd-la-button cd-la-button--secondary" data-ysv-sample-sigma><?php esc_html_e( 'Load Sigma example', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--secondary" data-ysv-sample-yara><?php esc_html_e( 'Load YARA example', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--ghost" data-ysv-clear><?php esc_html_e( 'Clear', 'cyberdat' ); ?></button>
			</div>
			<details class="cd-ysv-convert">
				<summary><?php esc_html_e( 'Convert Sigma to a query', 'cyberdat' ); ?></summary>
				<label class="cd-la-label" for="cd-ysv-target"><?php esc_html_e( 'Query language', 'cyberdat' ); ?></label>
				<select id="cd-ysv-target" class="cd-la-text cd-ysv-select notranslate" translate="no" data-ysv-target>
					<option value=""><?php esc_html_e( 'No conversion', 'cyberdat' ); ?></option>
					<option value="spl"><?php esc_html_e( 'Splunk SPL', 'cyberdat' ); ?></option>
					<option value="kql"><?php esc_html_e( 'Microsoft KQL', 'cyberdat' ); ?></option>
					<option value="lucene"><?php esc_html_e( 'Elastic Lucene', 'cyberdat' ); ?></option>
				</select>
				<label class="cd-la-label" for="cd-ysv-fieldmap"><?php esc_html_e( 'Field mapping (JSON, optional)', 'cyberdat' ); ?></label>
				<textarea id="cd-ysv-fieldmap" <?php echo $cyberdat_ysv_ta; // phpcs:ignore WordPress.Security.EscapeOutput -- static attribute string ?> rows="5" aria-describedby="cd-ysv-fieldmap-help" data-ysv-fieldmap></textarea>
				<p id="cd-ysv-fieldmap-help" class="cd-la-help"><?php esc_html_e( 'Maps Sigma field names to your field names, for example {"Image": "process.executable"}. Fields not listed are used as written.', 'cyberdat' ); ?></p>
				<button type="button" class="cd-la-button cd-la-button--ghost" data-ysv-fieldmap-example><?php esc_html_e( 'Load example mapping', 'cyberdat' ); ?></button>
				<p class="cd-la-help"><?php esc_html_e( 'Supported: field/value maps, value lists, keyword lists, the modifiers contains, startswith, endswith, all and exists, re and cidr (KQL and Lucene only), null values, numbers, the * wildcard (all) and ? (Lucene only), and conditions with and, or, not, parentheses, “1 of …” and “all of …”. Anything else stops the conversion with a message naming the construct.', 'cyberdat' ); ?></p>
			</details>
		</section>

		<div class="cd-la-actions">
			<button type="button" class="cd-la-button cd-la-button--primary" data-ysv-run><?php esc_html_e( 'Check rule', 'cyberdat' ); ?></button>
			<button type="button" class="cd-la-button cd-la-button--ghost" data-ysv-cancel hidden><?php esc_html_e( 'Cancel', 'cyberdat' ); ?></button>
			<progress class="cd-la-progress" max="100" value="0" aria-label="<?php esc_attr_e( 'Progress', 'cyberdat' ); ?>" data-ysv-progress hidden></progress>
		</div>
		<p class="cd-la-status" role="status" aria-live="polite" data-ysv-status></p>
		<div class="cd-la-callout cd-la-callout--error notranslate" translate="no" role="alert" data-ysv-error hidden></div>

		<section class="cd-la-panel cd-la-results notranslate" translate="no" aria-labelledby="cd-ysv-step-results" data-ysv-results hidden>
			<h2 id="cd-ysv-step-results" class="cd-la-step" tabindex="-1"><span aria-hidden="true">2</span> <b class="cd-ysv-step-title"><?php esc_html_e( 'Review the findings', 'cyberdat' ); ?></b></h2>
			<p class="cd-ysv-verdict" data-ysv-verdict></p>
			<p class="cd-la-summary" data-ysv-summary></p>
			<ul class="cd-ysv-notes" data-ysv-notes hidden></ul>
			<ol class="cd-ysv-findings" aria-label="<?php esc_attr_e( 'Findings', 'cyberdat' ); ?>" data-ysv-list></ol>
			<div class="cd-ysv-conv" data-ysv-conv hidden>
				<h3 class="cd-la-subheading" data-ysv-conv-title></h3>
				<div class="cd-la-callout cd-la-callout--warning" data-ysv-conv-secret hidden>
					<label class="cd-la-check"><input type="checkbox" data-ysv-conv-ack> <span><?php esc_html_e( 'The query contains values that look like secrets. Show it anyway.', 'cyberdat' ); ?></span></label>
				</div>
				<div data-ysv-conv-out></div>
			</div>
			<div class="cd-la-row">
				<button type="button" class="cd-la-button cd-la-button--secondary" data-ysv-report="markdown"><?php esc_html_e( 'Download report (Markdown)', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--secondary" data-ysv-report="json"><?php esc_html_e( 'Download report (JSON)', 'cyberdat' ); ?></button>
			</div>
			<p class="cd-la-help"><?php esc_html_e( 'The report contains the findings and converted queries with values that look like secrets masked. It does not contain the full rule.', 'cyberdat' ); ?></p>
		</section>
	</div>

	<div class="cd-la-info">
		<section aria-labelledby="cd-ysv-how">
			<h2 id="cd-ysv-how"><?php esc_html_e( 'How it works', 'cyberdat' ); ?></h2>
			<ol>
				<li><?php esc_html_e( 'Sigma: a YAML reader written for this tool loads the rule with limits on size, depth and time and refuses anchors, aliases and tags. CyberDat checks then look at required fields, log source, detection and condition, references to missing search identifiers, value modifiers, id, dates, level, status and tags, and give quality advice such as missing false positives, overly broad values and duplicates.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Conversion: the condition and search identifiers are turned into a Splunk SPL search, a Microsoft KQL where expression or an Elastic Lucene query by CyberDat code, with your field mapping. Constructs that are not supported are named in an error instead of producing a wrong query.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'YARA: the rule text is tokenized and checked statically: names and tags, meta values, strings and their modifiers, hex strings, regular expressions, declared and used strings, and modules used in the condition. Quality advice covers short strings, slow regular expressions and conditions without a file size limit.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Regular expressions written in rules are never executed; they are checked as text.', 'cyberdat' ); ?></li>
			</ol>
			<p class="cd-la-meta"><?php printf( esc_html__( 'Engine %1$s · rules %2$s', 'cyberdat' ), esc_html( $cyberdat_ysv['engine_version'] ), esc_html( $cyberdat_ysv['ruleset'] ) ); ?></p>
		</section>
		<section aria-labelledby="cd-ysv-privacy">
			<h2 id="cd-ysv-privacy"><?php esc_html_e( 'Privacy', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'This tool does not transmit the text you enter. The page has no server endpoint for your data, and its Content Security Policy blocks scripts on this page from opening network connections. Host names, paths and indicators in your rules stay in this tab.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Input fields, findings and queries are marked so that the browser’s built-in page translator does not translate them, because translating would send their text to a translation service.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'If you select Cancel (or processing times out), the background worker is restarted and the browser downloads its static script files again from this site. Those requests contain no part of your input.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'This tool does not persist data: input, findings and settings are not written to cookies, local storage or the address bar, and the tool resets them when you close or reload the tab. Browser session restore, extensions, the clipboard and downloaded files are outside these controls; this is not secure erasure.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Values in rules that look like secrets are shown masked in findings and reports; masking is best effort.', 'cyberdat' ); ?></li>
			</ul>
		</section>
		<section aria-labelledby="cd-ysv-limits">
			<h2 id="cd-ysv-limits"><?php esc_html_e( 'Limitations', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'Syntax checks do not replace compiling a rule with the official YARA engine or Sigma tooling and testing it on real data. A converted query must be checked in your own SIEM before you rely on it.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'The YARA check is static: it does not evaluate conditions, does not know every module function and can miss errors that the YARA compiler finds.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'The YAML reader supports the subset used by Sigma rules. Anchors, aliases, tags and merge keys are refused; Sigma rule collections (action:) and correlation rules are checked document by document and not converted.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Conversion does not handle log source mappings, pipelines, aggregations or the modifiers not listed above. Case-insensitive matching depends on your SIEM and field types.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Input up to 1 MB. Processing stops after 30 seconds.', 'cyberdat' ); ?></li>
			</ul>
		</section>
		<section aria-labelledby="cd-ysv-sources">
			<h2 id="cd-ysv-sources"><?php esc_html_e( 'Sources', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'All checks, conversions, explanations and example rules are written by CyberDat. No rule collection is bundled; no rules from the SigmaHQ repository are included.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Background reading: the Sigma specification by the SigmaHQ project (public domain) and the YARA documentation by the YARA authors (BSD 3-Clause). They are referenced here by name only; no text is copied.', 'cyberdat' ); ?></li>
			</ul>
		</section>
	</div>
</div>
