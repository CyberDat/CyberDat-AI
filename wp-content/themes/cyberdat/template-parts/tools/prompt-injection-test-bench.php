<?php
/**
 * LLM Prompt Injection Test Bench — interactive workspace markup.
 * Static, server-rendered UI only. Test sets are built and responses are checked in the browser by
 * assets/js/prompt-injection-test-bench/*.js; this tool sends nothing to any application and nothing to WordPress.
 * Inputs, test texts, responses and results carry translate="no" and the notranslate class.
 * Shared .cd-la-* classes come from assets/css/tools-common.css.
 */
defined( 'ABSPATH' ) || exit;
$cyberdat_pitb = cyberdat_pitb_config();
$cyberdat_pitb_ta = 'class="cd-la-input notranslate" translate="no" spellcheck="false" autocomplete="off" autocapitalize="off" autocorrect="off" data-gramm="false" data-gramm_editor="false" data-enable-grammarly="false" data-lt-active="false"';
?>
<div class="cd-la cd-pitb" data-pitb data-worker-state="loading" data-worker-src="<?php echo esc_url( $cyberdat_pitb['worker'] ); ?>">
	<noscript><p class="cd-la-callout cd-la-callout--warning"><?php esc_html_e( 'This tool needs JavaScript. Everything happens only in your browser, so nothing can run without it — and nothing is uploaded.', 'cyberdat' ); ?></p></noscript>
	<p class="cd-la-callout cd-la-callout--error" data-pitb-unsupported hidden><?php esc_html_e( 'Your browser does not support the background processing this tool needs (Web Workers). Try a current version of Edge, Chrome, Firefox or Safari.', 'cyberdat' ); ?></p>

	<div class="cd-la-app" data-pitb-app hidden>
		<p class="cd-la-callout cd-la-callout--privacy"><strong><?php esc_html_e( 'Local only.', 'cyberdat' ); ?></strong> <?php esc_html_e( 'Your text is analyzed in this browser tab. This tool does not transmit the text you enter — not to CyberDat, not to analytics, not to any AI service — and this tool does not write it to persistent browser storage.', 'cyberdat' ); ?></p>
		<p class="cd-la-callout cd-la-callout--warning" role="note"><strong><?php esc_html_e( 'Test only systems you are authorized to test.', 'cyberdat' ); ?></strong> <?php esc_html_e( 'Every test asks the application only for a harmless, verifiable action with a unique canary code. This tool does not send anything: you run the tests in your own application and paste the responses back. If no canary appears, that does not mean the application is protected.', 'cyberdat' ); ?></p>
		<p class="cd-pitb-state" role="status" aria-live="polite" data-pitb-worker-status><?php esc_html_e( 'Starting the local test engine…', 'cyberdat' ); ?></p>

		<section class="cd-la-panel" aria-labelledby="cd-pitb-step-build">
			<h2 id="cd-pitb-step-build" class="cd-la-step"><span aria-hidden="true">1</span> <?php esc_html_e( 'Build a test set', 'cyberdat' ); ?></h2>
			<fieldset class="cd-la-fieldset">
				<legend><?php esc_html_e( 'What kind of application is it?', 'cyberdat' ); ?></legend>
				<div class="cd-la-checks">
					<?php foreach ( cyberdat_pitb_app_types() as $cyberdat_key => $cyberdat_label ) : ?>
						<label class="cd-la-check"><input type="checkbox" value="<?php echo esc_attr( $cyberdat_key ); ?>" data-pitb-app-type<?php echo 'chat' === $cyberdat_key ? ' checked' : ''; ?>> <span><?php echo esc_html( $cyberdat_label ); ?></span></label>
					<?php endforeach; ?>
				</div>
			</fieldset>
			<fieldset class="cd-la-fieldset">
				<legend><?php esc_html_e( 'Languages of the tests', 'cyberdat' ); ?></legend>
				<div class="cd-la-checks">
					<label class="cd-la-check"><input type="checkbox" value="en" data-pitb-lang checked> <span><?php esc_html_e( 'English', 'cyberdat' ); ?></span></label>
					<label class="cd-la-check"><input type="checkbox" value="de" data-pitb-lang> <span><?php esc_html_e( 'German', 'cyberdat' ); ?></span></label>
					<label class="cd-la-check"><input type="checkbox" value="ru" data-pitb-lang> <span><?php esc_html_e( 'Russian', 'cyberdat' ); ?></span></label>
				</div>
			</fieldset>
			<div class="cd-la-row">
				<button type="button" class="cd-la-button cd-la-button--primary" data-pitb-build><?php esc_html_e( 'Build test set', 'cyberdat' ); ?></button>
				<label class="cd-la-file">
					<span class="cd-la-button cd-la-button--secondary" aria-hidden="true"><?php esc_html_e( 'Load a saved test set (JSONL)', 'cyberdat' ); ?></span>
					<input class="cd-la-file__input notranslate" translate="no" type="file" accept=".jsonl,.json,.txt,application/json,text/plain" aria-label="<?php esc_attr_e( 'Load a saved test set (JSONL)', 'cyberdat' ); ?>" data-pitb-set-file>
				</label>
			</div>
		</section>

		<section class="cd-la-panel notranslate" translate="no" aria-labelledby="cd-pitb-step-run" data-pitb-set hidden>
			<h2 id="cd-pitb-step-run" class="cd-la-step" tabindex="-1"><span aria-hidden="true">2</span> <b class="cd-pitb-step-title"><?php esc_html_e( 'Run the tests in your application', 'cyberdat' ); ?></b></h2>
			<p class="cd-la-summary" data-pitb-set-summary></p>
			<div class="cd-la-callout cd-la-callout--privacy cd-pitb-label">
				<p class="cd-pitb-label__text" data-pitb-label></p>
			</div>
			<div class="cd-la-row">
				<button type="button" class="cd-la-button cd-la-button--secondary" data-pitb-download="jsonl"><?php esc_html_e( 'Download test set (JSONL)', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--secondary" data-pitb-download="csv"><?php esc_html_e( 'Download test set (CSV)', 'cyberdat' ); ?></button>
			</div>
			<p class="cd-la-help"><?php esc_html_e( 'The downloaded set contains the canary codes, so you can check responses later by loading it again. Paste each response below, or paste all responses at once.', 'cyberdat' ); ?></p>
			<ol class="cd-pitb-tests" data-pitb-tests></ol>
			<details class="cd-pitb-bulk">
				<summary><?php esc_html_e( 'Paste all responses at once (JSONL or CSV)', 'cyberdat' ); ?></summary>
				<label class="cd-la-label" for="cd-pitb-bulk"><?php esc_html_e( 'Responses', 'cyberdat' ); ?></label>
				<textarea id="cd-pitb-bulk" <?php echo $cyberdat_pitb_ta; // phpcs:ignore WordPress.Security.EscapeOutput -- static attribute string ?> rows="6" aria-describedby="cd-pitb-bulk-help" data-pitb-bulk></textarea>
				<p id="cd-pitb-bulk-help" class="cd-la-help"><?php esc_html_e( 'One {"id": "T001", "response": "…"} object per line, or CSV with the columns id and response. Up to 5 MB in total and 200,000 characters per response.', 'cyberdat' ); ?></p>
				<button type="button" class="cd-la-button cd-la-button--secondary" data-pitb-bulk-apply><?php esc_html_e( 'Fill in the responses', 'cyberdat' ); ?></button>
			</details>
			<div class="cd-la-actions">
				<button type="button" class="cd-la-button cd-la-button--primary" data-pitb-check><?php esc_html_e( 'Check responses', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--ghost" data-pitb-cancel hidden><?php esc_html_e( 'Cancel', 'cyberdat' ); ?></button>
				<progress class="cd-la-progress" max="100" value="0" aria-label="<?php esc_attr_e( 'Progress', 'cyberdat' ); ?>" data-pitb-progress hidden></progress>
			</div>
		</section>

		<p class="cd-la-status" role="status" aria-live="polite" data-pitb-status></p>
		<div class="cd-la-callout cd-la-callout--error notranslate" translate="no" role="alert" data-pitb-error hidden></div>

		<section class="cd-la-panel cd-la-results notranslate" translate="no" aria-labelledby="cd-pitb-step-results" data-pitb-results hidden>
			<h2 id="cd-pitb-step-results" class="cd-la-step" tabindex="-1"><span aria-hidden="true">3</span> <b class="cd-pitb-step-title"><?php esc_html_e( 'Results', 'cyberdat' ); ?></b></h2>
			<p class="cd-pitb-verdict" data-pitb-verdict></p>
			<p class="cd-la-summary" data-pitb-summary></p>
			<div class="cd-la-table-wrap">
				<table class="cd-la-table cd-pitb-table">
					<caption><?php esc_html_e( 'Result per test', 'cyberdat' ); ?></caption>
					<thead><tr><th scope="col"><?php esc_html_e( 'Test', 'cyberdat' ); ?></th><th scope="col"><?php esc_html_e( 'Category', 'cyberdat' ); ?></th><th scope="col"><?php esc_html_e( 'Language', 'cyberdat' ); ?></th><th scope="col"><?php esc_html_e( 'Result', 'cyberdat' ); ?></th><th scope="col"><?php esc_html_e( 'Found as', 'cyberdat' ); ?></th><th scope="col"><?php esc_html_e( 'Response fragment (secrets masked)', 'cyberdat' ); ?></th></tr></thead>
					<tbody data-pitb-rows></tbody>
				</table>
			</div>
			<div class="cd-la-row">
				<button type="button" class="cd-la-button cd-la-button--secondary" data-pitb-report="markdown"><?php esc_html_e( 'Download report (Markdown)', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--secondary" data-pitb-report="json"><?php esc_html_e( 'Download report (JSON)', 'cyberdat' ); ?></button>
			</div>
			<p class="cd-la-help"><?php esc_html_e( 'The report contains the result per test and short response fragments with recognized secrets masked, not the full responses.', 'cyberdat' ); ?></p>
		</section>
	</div>

	<div class="cd-la-info">
		<section aria-labelledby="cd-pitb-how">
			<h2 id="cd-pitb-how"><?php esc_html_e( 'How it works', 'cyberdat' ); ?></h2>
			<ol>
				<li><?php esc_html_e( 'Choose the type of your application and the languages. The tool picks tests from a fixed CyberDat library of templates in ten categories, such as direct instruction override, injection in documents, emails and web pages, role and delimiter spoofing, hidden text, simple encodings, links that carry data, system-prompt label extraction and forced tool calls.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Each test gets its own canary code, for example CANARY-7F3A9C2B, and asks only for a harmless action: print the code, repeat a label you put into your system prompt, add an example.com link that carries the code, or call a tool named canary_echo with the code.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'You run the tests in your own application, in the channel each test names, and paste the responses back.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'The tool looks for each canary in its response, also when it is split, in another case, reversed, in a link, hidden with invisible or tag characters, written as HTML character references or JSON Unicode escapes, or encoded as Base64, hex or URL encoding, and shows which tests triggered. Only the whole code with its prefix counts as triggered (also with another separator between prefix and core, such as CANARY_7F3A9C2B), and only as a separate word: a longer code that merely starts with it does not count. The 8-character core alone, or the parts in another order, is shown as “Possible leak (core only)”: it is not a pass and it is not counted as triggered.', 'cyberdat' ); ?></li>
			</ol>
			<?php require_once dirname( __DIR__, 2 ) . '/inc/tools-owasp-2026.php'; ?>
			<p class="cd-la-meta"><?php printf( esc_html__( 'Engine %1$s · test library %2$s · test library updated %3$s', 'cyberdat' ), esc_html( $cyberdat_pitb['engine_version'] ), esc_html( $cyberdat_pitb['library'] ), esc_html( cyberdat_rules_updated( $cyberdat_pitb['library'] ) ) ); ?></p>
			<?php echo cyberdat_tools_owasp_line( 'prompt-injection-test-bench' ); // phpcs:ignore WordPress.Security.EscapeOutput -- escaped in the helper ?>
		</section>
		<section aria-labelledby="cd-pitb-privacy">
			<h2 id="cd-pitb-privacy"><?php esc_html_e( 'Privacy', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'This tool does not transmit the text you enter. The page has no server endpoint for your data, it does not call any AI model or external service, and its Content Security Policy blocks scripts on this page from opening network connections. It never sends tests to your application.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Inputs, test texts, responses and results are marked so that the browser’s built-in page translator does not translate them, because translating would send their text to a translation service.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'If you select Cancel (or processing times out), the background worker is restarted and the browser downloads its static script files again from this site. Those requests contain no part of your input.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'This tool does not persist data: input, findings and settings are not written to cookies, local storage or the address bar, and the tool resets them when you close or reload the tab. Browser session restore, extensions, the clipboard and downloaded files are outside these controls; this is not secure erasure.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Recognised secret values in responses and in imported test sets are shown only as their type and a masked fragment, on screen and in every export: known key formats, long random-looking values and the value after a key such as credential, password, pwd, secret, token, API key, X-Api-Key, access key, authorization, Bearer, csrf, session ID or cookie, whatever its length. Masking is best effort and does not find every secret.', 'cyberdat' ); ?></li>
			</ul>
		</section>
		<section aria-labelledby="cd-pitb-limits">
			<h2 id="cd-pitb-limits"><?php esc_html_e( 'Limitations', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'If no canary appears, that does not mean the application is protected. The library is small and fixed; real attacks use other wording, other channels and many attempts.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'The tests check only whether the application follows injected instructions for a harmless action. They do not test harmful content, safety policies or jailbreaks.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'A tool call can only be seen if you paste the tool-call log together with the response. Links and images are detected in the text; whether your interface would load them is not tested.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'A canary can be missed if the model rewrites it in a way not listed above, and models are not deterministic: run important tests several times.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Responses up to 200,000 characters each and 5 MB in total. Processing stops after 60 seconds.', 'cyberdat' ); ?></li>
			</ul>
		</section>
		<section aria-labelledby="cd-pitb-sources">
			<h2 id="cd-pitb-sources"><?php esc_html_e( 'Sources', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'The test library, the canary checks and all texts are written by CyberDat. No external prompt collection or attack set is bundled.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Links in tests use only reserved example domains (example.com, example.org, example.net).', 'cyberdat' ); ?></li>
			</ul>
		</section>
	</div>
</div>
