<?php
/**
 * Privacy Shield Log Anonymizer — interactive workspace markup.
 * Static, server-rendered UI only. All user input is handled in the browser by
 * assets/js/log-anonymizer/*.js and is never posted back to WordPress.
 */
defined( 'ABSPATH' ) || exit;
$cyberdat_la = cyberdat_log_anonymizer_config();
?>
<div class="cd-la" data-log-anonymizer data-worker-src="<?php echo esc_url( $cyberdat_la['worker'] ); ?>">
	<noscript><p class="cd-la-callout cd-la-callout--warning"><?php esc_html_e( 'This tool needs JavaScript. Processing happens only in your browser, so nothing can run without it — and nothing is uploaded.', 'cyberdat' ); ?></p></noscript>
	<p class="cd-la-callout cd-la-callout--error" data-la-unsupported hidden><?php esc_html_e( 'Your browser does not support the background processing this tool needs (Web Workers). Try a current version of Edge, Chrome, Firefox or Safari.', 'cyberdat' ); ?></p>

	<div class="cd-la-app" data-la-app hidden>
		<p class="cd-la-callout cd-la-callout--privacy"><strong><?php esc_html_e( 'Local only.', 'cyberdat' ); ?></strong> <?php esc_html_e( 'Your log is processed in this browser tab. The text you enter is never sent anywhere — not to CyberDat, not to analytics — and it is not stored.', 'cyberdat' ); ?></p>
		<p class="cd-la-callout cd-la-callout--warning" role="note"><strong><?php esc_html_e( 'Review before sharing.', 'cyberdat' ); ?></strong> <?php esc_html_e( 'Automated anonymization cannot guarantee that every secret or personal detail is removed. Check the result manually before you share it.', 'cyberdat' ); ?></p>

		<section class="cd-la-panel" aria-labelledby="cd-la-step-input">
			<h2 id="cd-la-step-input" class="cd-la-step"><span aria-hidden="true">1</span> <?php esc_html_e( 'Add your log', 'cyberdat' ); ?></h2>
			<label class="cd-la-label" for="cd-la-input"><?php esc_html_e( 'Log text', 'cyberdat' ); ?></label>
			<textarea id="cd-la-input" class="cd-la-input" rows="12" spellcheck="false" autocomplete="off" autocapitalize="off" autocorrect="off" data-gramm="false" data-gramm_editor="false" data-enable-grammarly="false" data-lt-active="false" aria-describedby="cd-la-input-help cd-la-source" data-la-input></textarea>
			<p id="cd-la-input-help" class="cd-la-help"><?php esc_html_e( 'Paste log lines or load a plain-text file (UTF-8 or UTF-16 with BOM, up to 50 MB). Files larger than 1 MB are processed in the background without being shown here.', 'cyberdat' ); ?></p>
			<div class="cd-la-row">
				<label class="cd-la-file">
					<span class="cd-la-button cd-la-button--secondary" aria-hidden="true"><?php esc_html_e( 'Load a text file', 'cyberdat' ); ?></span>
					<input class="cd-la-file__input" id="cd-la-file" type="file" accept=".log,.txt,.text,.json,.jsonl,.ndjson,.csv,.tsv,.xml,.yaml,.yml,.conf,.cfg,.ini,.out,.err,.har,text/plain,application/json" aria-label="<?php esc_attr_e( 'Load a text file', 'cyberdat' ); ?>" data-la-file>
				</label>
				<button type="button" class="cd-la-button cd-la-button--secondary" data-la-sample><?php esc_html_e( 'Load sample log', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--ghost" data-la-clear><?php esc_html_e( 'Clear everything', 'cyberdat' ); ?></button>
			</div>
			<p id="cd-la-source" class="cd-la-source" aria-live="polite" data-la-source></p>
		</section>

		<section class="cd-la-panel" aria-labelledby="cd-la-step-options">
			<h2 id="cd-la-step-options" class="cd-la-step"><span aria-hidden="true">2</span> <?php esc_html_e( 'Choose what to mask', 'cyberdat' ); ?></h2>
			<fieldset class="cd-la-fieldset">
				<legend><?php esc_html_e( 'Categories', 'cyberdat' ); ?></legend>
				<div class="cd-la-checks">
					<?php foreach ( $cyberdat_la['categories'] as $cyberdat_la_id => $cyberdat_la_cat ) : ?>
						<label class="cd-la-check">
							<input type="checkbox" checked value="<?php echo esc_attr( $cyberdat_la_id ); ?>" data-la-category data-short="<?php echo esc_attr( $cyberdat_la_cat['short'] ); ?>">
							<span><?php echo esc_html( $cyberdat_la_cat['label'] ); ?> <code class="cd-la-example"><?php echo esc_html( $cyberdat_la_cat['example'] ); ?></code></span>
						</label>
					<?php endforeach; ?>
				</div>
				<div class="cd-la-row cd-la-row--compact">
					<button type="button" class="cd-la-button cd-la-button--ghost" data-la-select="all"><?php esc_html_e( 'Select all', 'cyberdat' ); ?></button>
					<button type="button" class="cd-la-button cd-la-button--ghost" data-la-select="none"><?php esc_html_e( 'Select none', 'cyberdat' ); ?></button>
				</div>
			</fieldset>

			<fieldset class="cd-la-fieldset">
				<legend><?php esc_html_e( 'Replacement labels', 'cyberdat' ); ?></legend>
				<label class="cd-la-check">
					<input type="radio" name="cd-la-mode" value="stable" checked data-la-mode>
					<span><?php esc_html_e( 'Stable labels — the same value always gets the same label, so you can still follow it through the log', 'cyberdat' ); ?> <code class="cd-la-example">IPV4_1, IPV4_2</code></span>
				</label>
				<label class="cd-la-check">
					<input type="radio" name="cd-la-mode" value="generic" data-la-mode>
					<span><?php esc_html_e( 'Generic labels — every value of a category gets the same label', 'cyberdat' ); ?> <code class="cd-la-example">REDACTED_IPV4</code></span>
				</label>
			</fieldset>

			<label class="cd-la-check cd-la-check--standalone">
				<input type="checkbox" data-la-keep-private aria-describedby="cd-la-private-help">
				<span><?php esc_html_e( 'Keep private and loopback IPv4 addresses', 'cyberdat' ); ?></span>
			</label>
			<p id="cd-la-private-help" class="cd-la-help"><?php esc_html_e( 'Leaves 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8 and 169.254.0.0/16 unchanged. Internal addresses can still reveal your network layout.', 'cyberdat' ); ?></p>

			<fieldset class="cd-la-fieldset">
				<legend><?php esc_html_e( 'Custom rules', 'cyberdat' ); ?></legend>
				<p class="cd-la-help" id="cd-la-rules-help"><?php esc_html_e( 'Add your own JavaScript regular expressions, for example internal ticket or employee IDs. Each match is replaced with your label. Custom rules run first. Matches that span several lines are skipped so the log structure is kept.', 'cyberdat' ); ?></p>
				<ol class="cd-la-rules" data-la-rules></ol>
				<button type="button" class="cd-la-button cd-la-button--secondary" data-la-add-rule><?php esc_html_e( 'Add custom rule', 'cyberdat' ); ?></button>
				<template data-la-rule-template>
					<li class="cd-la-rule">
						<div class="cd-la-rule__field">
							<label class="cd-la-label" data-la-for="pattern"><?php esc_html_e( 'Pattern (regular expression)', 'cyberdat' ); ?></label>
							<input type="text" class="cd-la-text" spellcheck="false" autocomplete="off" autocapitalize="off" maxlength="1000" placeholder="EMP-\d{5}" data-la-rule-pattern>
							<p class="cd-la-field-error" data-la-rule-error="pattern" hidden></p>
						</div>
						<div class="cd-la-rule__field cd-la-rule__field--label">
							<label class="cd-la-label" data-la-for="label"><?php esc_html_e( 'Label', 'cyberdat' ); ?></label>
							<input type="text" class="cd-la-text" spellcheck="false" autocomplete="off" autocapitalize="characters" maxlength="32" placeholder="EMPLOYEE_ID" data-la-rule-label>
							<p class="cd-la-field-error" data-la-rule-error="label" hidden></p>
						</div>
						<label class="cd-la-check cd-la-rule__case"><input type="checkbox" data-la-rule-case> <span><?php esc_html_e( 'Ignore case', 'cyberdat' ); ?></span></label>
						<button type="button" class="cd-la-button cd-la-button--ghost" data-la-remove-rule><?php esc_html_e( 'Remove rule', 'cyberdat' ); ?></button>
					</li>
				</template>
			</fieldset>
		</section>

		<div class="cd-la-actions">
			<button type="button" class="cd-la-button cd-la-button--primary" data-la-run><?php esc_html_e( 'Anonymize log', 'cyberdat' ); ?></button>
			<button type="button" class="cd-la-button cd-la-button--ghost" data-la-cancel hidden><?php esc_html_e( 'Cancel', 'cyberdat' ); ?></button>
			<progress class="cd-la-progress" max="100" value="0" aria-label="<?php esc_attr_e( 'Anonymization progress', 'cyberdat' ); ?>" data-la-progress hidden></progress>
		</div>
		<p class="cd-la-status" role="status" aria-live="polite" data-la-status></p>
		<div class="cd-la-callout cd-la-callout--error" role="alert" data-la-error hidden></div>

		<section class="cd-la-panel cd-la-results" aria-labelledby="cd-la-step-results" data-la-results hidden>
			<h2 id="cd-la-step-results" class="cd-la-step" tabindex="-1"><span aria-hidden="true">3</span> <?php esc_html_e( 'Review the result', 'cyberdat' ); ?></h2>
			<p class="cd-la-summary" data-la-summary></p>
			<ul class="cd-la-notes" data-la-notes hidden></ul>
			<div class="cd-la-table-wrap">
				<table class="cd-la-table">
					<caption><?php esc_html_e( 'Replacements by category', 'cyberdat' ); ?></caption>
					<thead><tr><th scope="col"><?php esc_html_e( 'Category', 'cyberdat' ); ?></th><th scope="col"><?php esc_html_e( 'Replaced', 'cyberdat' ); ?></th><th scope="col"><?php esc_html_e( 'Unique values', 'cyberdat' ); ?></th></tr></thead>
					<tbody data-la-stats></tbody>
				</table>
			</div>
			<h3 class="cd-la-subheading" id="cd-la-preview-title"><?php esc_html_e( 'Preview', 'cyberdat' ); ?></h3>
			<p class="cd-la-help" id="cd-la-preview-help"><?php esc_html_e( 'Replaced values are highlighted. Everything that is not highlighted is unchanged — read it carefully.', 'cyberdat' ); ?></p>
			<pre class="cd-la-preview" tabindex="0" role="region" aria-labelledby="cd-la-preview-title" aria-describedby="cd-la-preview-help" data-la-preview></pre>
			<p class="cd-la-help" data-la-truncated hidden></p>
			<div class="cd-la-row">
				<button type="button" class="cd-la-button cd-la-button--primary" data-la-copy><?php esc_html_e( 'Copy result', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--secondary" data-la-download><?php esc_html_e( 'Download result', 'cyberdat' ); ?></button>
			</div>

			<div class="cd-la-map">
				<h3 class="cd-la-subheading"><?php esc_html_e( 'Replacement map', 'cyberdat' ); ?></h3>
				<p class="cd-la-callout cd-la-callout--warning" id="cd-la-map-warning"><strong><?php esc_html_e( 'Contains the original values.', 'cyberdat' ); ?></strong> <?php esc_html_e( 'The map lists every label next to the secret or personal value it replaced. Keep it private and never send it together with the anonymized log.', 'cyberdat' ); ?></p>
				<label class="cd-la-check cd-la-check--standalone"><input type="checkbox" data-la-map-ack aria-describedby="cd-la-map-warning"> <span><?php esc_html_e( 'I understand that the map contains sensitive original values', 'cyberdat' ); ?></span></label>
				<button type="button" class="cd-la-button cd-la-button--secondary" data-la-map disabled><?php esc_html_e( 'Download replacement map (JSON)', 'cyberdat' ); ?></button>
			</div>
		</section>
	</div>

	<div class="cd-la-info">
		<section aria-labelledby="cd-la-how">
			<h2 id="cd-la-how"><?php esc_html_e( 'How it works', 'cyberdat' ); ?></h2>
			<ol>
				<li><?php esc_html_e( 'Your text or file is read by a background worker inside this browser tab, so large logs do not freeze the page.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Versioned detection rules scan each line for the categories you selected. Payment card numbers must pass the Luhn checksum; IPv6 and IPv4 candidates are validated, not just pattern-matched.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Only the detected values are replaced. Line breaks, delimiters, field names and timestamps stay where they were, and the tool refuses to produce output if the number of lines would change.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'With stable labels, the same value receives the same label everywhere in one run, so you can still correlate events without revealing the value.', 'cyberdat' ); ?></li>
			</ol>
			<p class="cd-la-meta"><?php printf( esc_html__( 'Engine %1$s · rules %2$s', 'cyberdat' ), esc_html( $cyberdat_la['engine_version'] ), esc_html( $cyberdat_la['ruleset'] ) ); ?></p>
		</section>
		<section aria-labelledby="cd-la-privacy">
			<h2 id="cd-la-privacy"><?php esc_html_e( 'Privacy', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'The text you enter is never sent anywhere. The page has no server endpoint for your data, and its Content Security Policy blocks scripts on this page from opening network connections.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'If you select Cancel (or processing times out), the background worker is restarted and the browser downloads its two static script files again from this site. Those requests contain no part of your input.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Nothing is saved: input, results and settings are not written to cookies, local storage or the address bar, and they disappear when you close or reload the tab.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'No third parties: the page loads no external scripts, fonts or analytics.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Browser extensions you have installed can read page content. Use a private window without extensions for highly sensitive logs.', 'cyberdat' ); ?></li>
			</ul>
		</section>
		<section aria-labelledby="cd-la-limits">
			<h2 id="cd-la-limits"><?php esc_html_e( 'Limitations of automated analysis', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'Detection is pattern-based. Secrets without a recognizable format or key name (for example a bare random string), names of people, street addresses and phone numbers are not detected.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Hostnames are found from URLs, known key names, syslog headers and a list of top-level domains. Single-word hostnames outside those contexts are missed.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Four-part numbers such as 1.2.3.4 are treated as IPv4 addresses unless a version keyword precedes them. Some identifiers may be masked unnecessarily.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Values split across lines, encoded (Base64, URL-encoding inside other values) or in binary formats are not reliably detected. US SSNs are only detected in the 123-45-6789 format.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Stable labels are consistent within one run only. Labels and their order can reveal how many distinct users or hosts appear.', 'cyberdat' ); ?></li>
			</ul>
		</section>
	</div>
</div>
