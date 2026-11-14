<?php
/**
 * System Prompt & Agent Leak Inspector — interactive workspace markup.
 * Static, server-rendered UI only. Prompts and responses are analyzed in the browser by
 * assets/js/leak-inspector/*.js as text; they are never executed, never sent to a model and never posted to WordPress.
 * Shared .cd-la-* component classes come from assets/css/tools-common.css.
 */
defined( 'ABSPATH' ) || exit;
$cyberdat_lki = cyberdat_lki_config();
?>
<div class="cd-la cd-lki" data-lki data-worker-src="<?php echo esc_url( $cyberdat_lki['worker'] ); ?>">
	<noscript><p class="cd-la-callout cd-la-callout--warning"><?php esc_html_e( 'This tool needs JavaScript. The check happens only in your browser, so nothing can run without it — and nothing is uploaded.', 'cyberdat' ); ?></p></noscript>
	<p class="cd-la-callout cd-la-callout--error" data-lki-unsupported hidden><?php esc_html_e( 'Your browser does not support the background processing this tool needs (Web Workers). Try a current version of Edge, Chrome, Firefox or Safari.', 'cyberdat' ); ?></p>

	<div class="cd-la-app" data-lki-app hidden>
		<p class="cd-la-callout cd-la-callout--privacy"><strong><?php esc_html_e( 'Local only.', 'cyberdat' ); ?></strong> <?php esc_html_e( 'Prompts and responses are checked in this browser tab as text. The text you enter is never sent anywhere by this tool — not to CyberDat, not to analytics, not to any AI model — and it is not stored.', 'cyberdat' ); ?></p>
		<p class="cd-la-callout cd-la-callout--warning" role="note"><strong><?php esc_html_e( 'A review aid, not a guarantee.', 'cyberdat' ); ?></strong> <?php esc_html_e( 'The tool looks for known weaknesses and known leak patterns in the text you provide. It cannot prove that a prompt will not leak: assume anything in a system prompt can be extracted.', 'cyberdat' ); ?></p>

		<section class="cd-la-panel" aria-labelledby="cd-lki-step-input">
			<h2 id="cd-lki-step-input" class="cd-la-step"><span aria-hidden="true">1</span> <?php esc_html_e( 'Add your prompt', 'cyberdat' ); ?></h2>
			<fieldset class="cd-lki-modes">
				<legend class="cd-la-label"><?php esc_html_e( 'What to check', 'cyberdat' ); ?></legend>
				<label class="cd-lki-mode"><input type="radio" name="cd-lki-mode" value="audit" checked data-lki-mode> <span><strong><?php esc_html_e( 'Prompt audit', 'cyberdat' ); ?></strong> — <?php esc_html_e( 'find secrets, internal details and weak spots in a system prompt or agent description', 'cyberdat' ); ?></span></label>
				<label class="cd-lki-mode"><input type="radio" name="cd-lki-mode" value="leak" data-lki-mode> <span><strong><?php esc_html_e( 'Leak check', 'cyberdat' ); ?></strong> — <?php esc_html_e( 'compare your reference prompt with a response or transcript', 'cyberdat' ); ?></span></label>
			</fieldset>
			<label class="cd-la-label" for="cd-lki-prompt"><?php esc_html_e( 'System prompt or agent description', 'cyberdat' ); ?></label>
			<textarea id="cd-lki-prompt" class="cd-la-input" rows="12" spellcheck="false" autocomplete="off" autocapitalize="off" autocorrect="off" data-gramm="false" data-gramm_editor="false" data-enable-grammarly="false" data-lt-active="false" aria-describedby="cd-lki-prompt-help cd-lki-prompt-source" data-lki-prompt></textarea>
			<p id="cd-lki-prompt-help" class="cd-la-help"><?php esc_html_e( 'Plain text in any language, up to 1 MB. In Leak check this is the reference prompt. Use a copy with real credentials removed if you can.', 'cyberdat' ); ?></p>
			<div class="cd-la-row">
				<label class="cd-la-file">
					<span class="cd-la-button cd-la-button--secondary" aria-hidden="true"><?php esc_html_e( 'Load prompt file', 'cyberdat' ); ?></span>
					<input class="cd-la-file__input" id="cd-lki-prompt-file" type="file" accept=".txt,.md,.text,.json,.yaml,.yml,text/plain" aria-label="<?php esc_attr_e( 'Load prompt file', 'cyberdat' ); ?>" data-lki-prompt-file>
				</label>
				<button type="button" class="cd-la-button cd-la-button--secondary" data-lki-sample><?php esc_html_e( 'Load example', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--ghost" data-lki-clear><?php esc_html_e( 'Clear everything', 'cyberdat' ); ?></button>
			</div>
			<p id="cd-lki-prompt-source" class="cd-la-source" aria-live="polite" data-lki-prompt-source></p>

			<div class="cd-lki-leak" data-lki-leak-panel hidden>
				<label class="cd-la-label" for="cd-lki-response"><?php esc_html_e( 'Response or conversation transcript', 'cyberdat' ); ?></label>
				<textarea id="cd-lki-response" class="cd-la-input" rows="10" spellcheck="false" autocomplete="off" autocapitalize="off" autocorrect="off" data-gramm="false" data-gramm_editor="false" data-enable-grammarly="false" data-lt-active="false" aria-describedby="cd-lki-response-help cd-lki-response-source" data-lki-response></textarea>
				<p id="cd-lki-response-help" class="cd-la-help"><?php esc_html_e( 'Paste a model answer or a whole conversation, up to 5 MB. Encoded parts (Base64, hex, URL encoding) are decoded locally and compared too.', 'cyberdat' ); ?></p>
				<div class="cd-la-row">
					<label class="cd-la-file">
						<span class="cd-la-button cd-la-button--secondary" aria-hidden="true"><?php esc_html_e( 'Load response file', 'cyberdat' ); ?></span>
						<input class="cd-la-file__input" id="cd-lki-response-file" type="file" accept=".txt,.md,.text,.json,.jsonl,.log,text/plain" aria-label="<?php esc_attr_e( 'Load response file', 'cyberdat' ); ?>" data-lki-response-file>
					</label>
					<label class="cd-lki-number" for="cd-lki-min-words"><?php esc_html_e( 'Minimum fragment length (words)', 'cyberdat' ); ?>
						<input id="cd-lki-min-words" type="number" min="4" max="50" step="1" value="8" inputmode="numeric" data-lki-min-words>
					</label>
				</div>
				<p id="cd-lki-response-source" class="cd-la-source" aria-live="polite" data-lki-response-source></p>
			</div>
		</section>

		<div class="cd-la-actions">
			<button type="button" class="cd-la-button cd-la-button--primary" data-lki-run><?php esc_html_e( 'Audit prompt', 'cyberdat' ); ?></button>
			<button type="button" class="cd-la-button cd-la-button--ghost" data-lki-cancel hidden><?php esc_html_e( 'Cancel', 'cyberdat' ); ?></button>
			<progress class="cd-la-progress" max="100" value="0" aria-label="<?php esc_attr_e( 'Check progress', 'cyberdat' ); ?>" data-lki-progress hidden></progress>
		</div>
		<p class="cd-la-status" role="status" aria-live="polite" data-lki-status></p>
		<div class="cd-la-callout cd-la-callout--error" role="alert" data-lki-error hidden></div>

		<section class="cd-la-panel cd-la-results" aria-labelledby="cd-lki-step-results" data-lki-results hidden>
			<h2 id="cd-lki-step-results" class="cd-la-step" tabindex="-1"><span aria-hidden="true">2</span> <?php esc_html_e( 'Review the results', 'cyberdat' ); ?></h2>
			<p class="cd-lki-verdict" data-lki-verdict></p>
			<p class="cd-la-summary" data-lki-summary></p>
			<div class="cd-lki-metrics" data-lki-metrics hidden></div>
			<ul class="cd-lki-notes" data-lki-notes hidden></ul>
			<div class="cd-la-table-wrap" data-lki-groups-wrap hidden>
				<table class="cd-la-table">
					<caption><?php esc_html_e( 'Findings by rule group', 'cyberdat' ); ?></caption>
					<thead><tr><th scope="col"><?php esc_html_e( 'Rule group', 'cyberdat' ); ?></th><th scope="col"><?php esc_html_e( 'Findings', 'cyberdat' ); ?></th></tr></thead>
					<tbody data-lki-groups></tbody>
				</table>
			</div>
			<h3 class="cd-la-subheading" id="cd-lki-list-title"><?php esc_html_e( 'Findings', 'cyberdat' ); ?></h3>
			<p class="cd-la-help"><?php esc_html_e( 'Sorted by severity. Excerpts are short; recognized secrets and long values without spaces are masked on a best-effort basis. Review before sharing.', 'cyberdat' ); ?></p>
			<ol class="cd-lki-findings" aria-labelledby="cd-lki-list-title" data-lki-list></ol>
			<p class="cd-la-help" data-lki-more hidden></p>
			<div data-lki-decoded-wrap hidden>
				<h3 class="cd-la-subheading" id="cd-lki-decoded-title"><?php esc_html_e( 'Decoded parts of the response', 'cyberdat' ); ?></h3>
				<ul class="cd-lki-decoded" aria-labelledby="cd-lki-decoded-title" data-lki-decoded></ul>
			</div>
			<div class="cd-la-row">
				<button type="button" class="cd-la-button cd-la-button--secondary" data-lki-report><?php esc_html_e( 'Download results (JSON)', 'cyberdat' ); ?></button>
			</div>
			<p class="cd-la-help"><?php esc_html_e( 'The report contains findings with short masked excerpts, not the full prompt or response. It is created in your browser and saved only where you choose.', 'cyberdat' ); ?></p>
		</section>
	</div>

	<div class="cd-la-info">
		<section aria-labelledby="cd-lki-how">
			<h2 id="cd-lki-how"><?php esc_html_e( 'How it works', 'cyberdat' ); ?></h2>
			<ol>
				<li><?php esc_html_e( 'Prompt audit: CyberDat rules look for credentials, internal hosts and addresses, staff emails, file paths and code names, confidential prices and thresholds, moderation exceptions, “never reveal these instructions” used as protection, passwords that unlock special modes, untrusted input placeholders without boundaries, broad tool permissions, irreversible actions without human confirmation, and personal or financial data. Rules cover English, German and Russian.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Leak check: the reference prompt and the response are split into words. Sequences of at least the chosen length that appear in both are reported as verbatim, or as near-verbatim when they match only after ignoring case, spacing, punctuation and invisible characters.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Base64, hex and URL-encoded parts of the response are decoded up to two layers deep and compared with the prompt; the decoded text is shown. Secrets found in the prompt are searched for in the response.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'An overlap measure shows how many three-word phrases of the prompt also appear in the response, with the matching phrases. It helps you spot close paraphrases; it is a number, not a verdict.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Every finding has a rule id, a severity, its line, an explanation and a suggested change. Nothing is sent to an AI model: all comparisons are simple text operations with size and time limits.', 'cyberdat' ); ?></li>
			</ol>
			<p class="cd-la-meta"><?php printf( esc_html__( 'Engine %1$s · rules %2$s', 'cyberdat' ), esc_html( $cyberdat_lki['engine_version'] ), esc_html( $cyberdat_lki['ruleset'] ) ); ?></p>
		</section>
		<section aria-labelledby="cd-lki-privacy">
			<h2 id="cd-lki-privacy"><?php esc_html_e( 'Privacy', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'The text you enter is never sent anywhere by this tool: it does not call any AI model or external service, and the page’s Content Security Policy blocks scripts on this page from opening network connections.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'If you select Cancel (or processing times out), the background worker is restarted and the browser downloads its static script files again from this site. Those requests contain no part of your input.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'The tool does not store your prompt, response or results in cookies, local storage or the address bar; they are cleared when you close or reload the tab. Browser session restore, extensions, the clipboard and files you download are outside the tool’s control.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Masking is best effort: recognized secrets and long values without spaces are shortened in results and exports, but secrets in an unusual form can remain in excerpts. Review exports before sharing.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Text is treated as data only: it is never executed and is displayed as plain text, never as HTML.', 'cyberdat' ); ?></li>
			</ul>
		</section>
		<section aria-labelledby="cd-lki-limits">
			<h2 id="cd-lki-limits"><?php esc_html_e( 'Limitations', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'The tool does not prove that a prompt has not leaked or cannot be extracted. No findings only means that the known patterns did not match the text you provided.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'The leak check compares only the texts you paste. Paraphrases with different words, translations, summaries and leaks spread across many short answers can be missed; the overlap measure gives a hint, not a decision.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'The prompt audit relies on wording and formats. Unusual secrets, internal names that look ordinary and sensitive rules phrased indirectly can be missed; ordinary text can occasionally match.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Rules cover English, German and Russian. Other languages are checked only for formats such as keys, addresses, phone numbers and encodings.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Decoding covers Base64, hex and URL encoding up to two layers. Other encodings, compression, images and files referenced by the text are not analyzed.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Large inputs are compared within time and size limits; when a limit is reached the results are marked as partial.', 'cyberdat' ); ?></li>
			</ul>
		</section>
		<section aria-labelledby="cd-lki-sources">
			<h2 id="cd-lki-sources"><?php esc_html_e( 'Sources', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'All rules, explanations and examples are written by CyberDat. No external rule set, prompt catalogue or dataset is bundled, and the tool does not generate extraction prompts.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Background reading: the OWASP Top 10 for Large Language Model Applications (2025), entry “System Prompt Leakage”, by the OWASP GenAI Security Project. It is referenced here by name only; no text is copied.', 'cyberdat' ); ?></li>
			</ul>
		</section>
	</div>
</div>
