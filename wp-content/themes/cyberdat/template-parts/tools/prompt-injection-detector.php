<?php
/**
 * Indirect Prompt Injection Sanitizer & Detector — interactive workspace markup.
 * Static, server-rendered UI only. All user input is handled in the browser by
 * assets/js/prompt-injection-detector/*.js and is never posted back to WordPress.
 * Shared .cd-la-* component classes come from assets/css/tools-common.css.
 */
defined( 'ABSPATH' ) || exit;
$cyberdat_pi = cyberdat_prompt_detector_config();
?>
<div class="cd-la cd-pi" data-prompt-detector data-worker-src="<?php echo esc_url( $cyberdat_pi['worker'] ); ?>">
	<noscript><p class="cd-la-callout cd-la-callout--warning"><?php esc_html_e( 'This tool needs JavaScript. Analysis happens only in your browser, so nothing can run without it — and nothing is uploaded.', 'cyberdat' ); ?></p></noscript>
	<p class="cd-la-callout cd-la-callout--error" data-pi-unsupported hidden><?php esc_html_e( 'Your browser does not support the background processing this tool needs (Web Workers). Try a current version of Edge, Chrome, Firefox or Safari.', 'cyberdat' ); ?></p>

	<div class="cd-la-app" data-pi-app hidden>
		<p class="cd-la-callout cd-la-callout--privacy"><strong><?php esc_html_e( 'Local only.', 'cyberdat' ); ?></strong> <?php esc_html_e( 'Your text is analyzed in this browser tab. The text you enter is never sent anywhere — not to CyberDat, not to analytics, not to any AI service — and it is not stored.', 'cyberdat' ); ?></p>
		<p class="cd-la-callout cd-la-callout--warning" role="note"><strong><?php esc_html_e( 'No guarantee of safety.', 'cyberdat' ); ?></strong> <?php esc_html_e( 'Automated analysis cannot detect every prompt injection: a reworded attack can pass every rule. A result without findings does not make a text safe, and neither the original nor the sanitized copy should be treated as trusted instructions.', 'cyberdat' ); ?></p>

		<section class="cd-la-panel" aria-labelledby="cd-pi-step-input">
			<h2 id="cd-pi-step-input" class="cd-la-step"><span aria-hidden="true">1</span> <?php esc_html_e( 'Add the untrusted text', 'cyberdat' ); ?></h2>
			<label class="cd-la-label" for="cd-pi-input"><?php esc_html_e( 'Text to analyze', 'cyberdat' ); ?></label>
			<textarea id="cd-pi-input" class="cd-la-input cd-pi-input" rows="12" spellcheck="false" autocomplete="off" autocapitalize="off" autocorrect="off" data-gramm="false" data-gramm_editor="false" data-enable-grammarly="false" data-lt-active="false" aria-describedby="cd-pi-input-help cd-pi-source" data-pi-input></textarea>
			<p id="cd-pi-input-help" class="cd-la-help"><?php esc_html_e( 'Paste text that an AI assistant or agent would read: a web page (HTML source works best), an email, a document, search results or tool output. You can also load a plain-text file (UTF-8 or UTF-16 with BOM, up to 20 MB). Files larger than 1 MB are analyzed in the background without being shown here.', 'cyberdat' ); ?></p>
			<div class="cd-la-row">
				<label class="cd-la-file">
					<span class="cd-la-button cd-la-button--secondary" aria-hidden="true"><?php esc_html_e( 'Load a text file', 'cyberdat' ); ?></span>
					<input class="cd-la-file__input" id="cd-pi-file" type="file" accept=".txt,.text,.md,.markdown,.html,.htm,.xml,.json,.jsonl,.csv,.eml,.log,.yaml,.yml,text/plain,text/html,text/markdown,application/json" aria-label="<?php esc_attr_e( 'Load a text file', 'cyberdat' ); ?>" data-pi-file>
				</label>
				<button type="button" class="cd-la-button cd-la-button--secondary" data-pi-sample><?php esc_html_e( 'Load example', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--ghost" data-pi-clear><?php esc_html_e( 'Clear everything', 'cyberdat' ); ?></button>
			</div>
			<p id="cd-pi-source" class="cd-la-source" aria-live="polite" data-pi-source></p>
			<p class="cd-la-callout cd-la-callout--warning cd-pi-large" data-pi-large hidden></p>
		</section>

		<section class="cd-la-panel" aria-labelledby="cd-pi-step-options">
			<h2 id="cd-pi-step-options" class="cd-la-step"><span aria-hidden="true">2</span> <?php esc_html_e( 'Sanitized copy options', 'cyberdat' ); ?></h2>
			<p class="cd-la-help cd-pi-options-help"><?php esc_html_e( 'Detection always runs on a normalized copy of the text and is not affected by these options. They only control what the sanitized copy changes.', 'cyberdat' ); ?></p>
			<fieldset class="cd-la-fieldset">
				<legend><?php esc_html_e( 'Normalization', 'cyberdat' ); ?></legend>
				<label class="cd-la-check">
					<input type="checkbox" checked data-pi-opt="removeInvisible">
					<span><?php esc_html_e( 'Remove invisible and bidirectional control characters', 'cyberdat' ); ?> <code class="cd-la-example"><?php esc_html_e( 'zero-width, Unicode tags, bidi overrides; emoji joiners are kept', 'cyberdat' ); ?></code></span>
				</label>
				<label class="cd-la-check">
					<input type="checkbox" checked data-pi-opt="normalizeNFKC">
					<span><?php esc_html_e( 'Apply Unicode NFKC normalization', 'cyberdat' ); ?> <code class="cd-la-example"><?php esc_html_e( 'ｆｕｌｌｗｉｄｔｈ → fullwidth, ﬁ → fi, ² → 2 (can change the meaning of some symbols)', 'cyberdat' ); ?></code></span>
				</label>
			</fieldset>
			<fieldset class="cd-la-fieldset">
				<legend><?php esc_html_e( 'Replace flagged passages', 'cyberdat' ); ?></legend>
				<label class="cd-la-check"><input type="radio" name="cd-pi-neutralize" value="low" checked data-pi-neutralize> <span><?php esc_html_e( 'All findings, including low severity', 'cyberdat' ); ?></span></label>
				<label class="cd-la-check"><input type="radio" name="cd-pi-neutralize" value="medium" data-pi-neutralize> <span><?php esc_html_e( 'Medium and high severity', 'cyberdat' ); ?></span></label>
				<label class="cd-la-check"><input type="radio" name="cd-pi-neutralize" value="high" data-pi-neutralize> <span><?php esc_html_e( 'High severity only', 'cyberdat' ); ?></span></label>
				<label class="cd-la-check"><input type="radio" name="cd-pi-neutralize" value="none" data-pi-neutralize> <span><?php esc_html_e( 'Do not replace anything (normalization only)', 'cyberdat' ); ?></span></label>
			</fieldset>
		</section>

		<div class="cd-la-actions">
			<button type="button" class="cd-la-button cd-la-button--primary" data-pi-run><?php esc_html_e( 'Analyze text', 'cyberdat' ); ?></button>
			<button type="button" class="cd-la-button cd-la-button--ghost" data-pi-cancel hidden><?php esc_html_e( 'Cancel', 'cyberdat' ); ?></button>
			<progress class="cd-la-progress" max="100" value="0" aria-label="<?php esc_attr_e( 'Analysis progress', 'cyberdat' ); ?>" data-pi-progress hidden></progress>
		</div>
		<p class="cd-la-status" role="status" aria-live="polite" data-pi-status></p>
		<div class="cd-la-callout cd-la-callout--error" role="alert" data-pi-error hidden></div>

		<section class="cd-la-panel cd-la-results" aria-labelledby="cd-pi-step-results" data-pi-results hidden>
			<h2 id="cd-pi-step-results" class="cd-la-step" tabindex="-1"><span aria-hidden="true">3</span> <?php esc_html_e( 'Review the findings', 'cyberdat' ); ?></h2>
			<p class="cd-pi-verdict" data-pi-verdict></p>
			<p class="cd-la-summary" data-pi-summary></p>
			<ul class="cd-la-notes" data-pi-notes hidden></ul>
			<div class="cd-la-table-wrap">
				<table class="cd-la-table cd-pi-table">
					<caption><?php esc_html_e( 'Findings by rule group and severity', 'cyberdat' ); ?></caption>
					<thead><tr><th scope="col"><?php esc_html_e( 'Rule group', 'cyberdat' ); ?></th><th scope="col"><?php esc_html_e( 'High', 'cyberdat' ); ?></th><th scope="col"><?php esc_html_e( 'Medium', 'cyberdat' ); ?></th><th scope="col"><?php esc_html_e( 'Low', 'cyberdat' ); ?></th></tr></thead>
					<tbody data-pi-groups></tbody>
				</table>
			</div>

			<h3 class="cd-la-subheading" id="cd-pi-findings-title"><?php esc_html_e( 'Findings', 'cyberdat' ); ?></h3>
			<p class="cd-la-help" data-pi-findings-empty hidden><?php esc_html_e( 'No rule matched. This only means that none of the known patterns was found; the text can still contain an injection.', 'cyberdat' ); ?></p>
			<ol class="cd-pi-findings" aria-labelledby="cd-pi-findings-title" data-pi-findings></ol>
			<p class="cd-la-help" data-pi-findings-more hidden></p>

			<h3 class="cd-la-subheading"><?php esc_html_e( 'Normalization and decoding', 'cyberdat' ); ?></h3>
			<p class="cd-la-help"><?php esc_html_e( 'Before matching, the tool removed invisible characters, applied Unicode NFKC and decoded encoded fragments. This is what changed or was decoded:', 'cyberdat' ); ?></p>
			<ul class="cd-pi-norm" data-pi-normalization></ul>
			<div class="cd-la-table-wrap" data-pi-decoded-wrap hidden>
				<table class="cd-la-table cd-pi-decoded">
					<caption><?php esc_html_e( 'Decoded fragments', 'cyberdat' ); ?></caption>
					<thead><tr><th scope="col"><?php esc_html_e( 'Position', 'cyberdat' ); ?></th><th scope="col"><?php esc_html_e( 'Encoding', 'cyberdat' ); ?></th><th scope="col"><?php esc_html_e( 'Decoded text', 'cyberdat' ); ?></th></tr></thead>
					<tbody data-pi-decoded></tbody>
				</table>
			</div>

			<h3 class="cd-la-subheading" id="cd-pi-highlight-title"><?php esc_html_e( 'Text with findings highlighted', 'cyberdat' ); ?></h3>
			<p class="cd-la-help" id="cd-pi-highlight-help"><?php esc_html_e( 'Invisible characters inside findings are shown as ⟨U+…⟩. Text that is not highlighted was not flagged, which does not mean it was checked as safe.', 'cyberdat' ); ?></p>
			<pre class="cd-la-preview cd-pi-preview" tabindex="0" role="region" aria-labelledby="cd-pi-highlight-title" aria-describedby="cd-pi-highlight-help" data-pi-highlight></pre>
			<p class="cd-la-help" data-pi-highlight-truncated hidden></p>
		</section>

		<section class="cd-la-panel cd-la-results" aria-labelledby="cd-pi-step-sanitized" data-pi-sanitized hidden>
			<h2 id="cd-pi-step-sanitized" class="cd-la-step"><span aria-hidden="true">4</span> <?php esc_html_e( 'Sanitized copy (secondary)', 'cyberdat' ); ?></h2>
			<p class="cd-la-callout cd-la-callout--warning"><strong><?php esc_html_e( 'Still untrusted.', 'cyberdat' ); ?></strong> <?php esc_html_e( 'The sanitized copy only removes what the rules recognized. Anything the rules missed is still in it, and normalization can change the meaning of some characters. Review every change below before you use it.', 'cyberdat' ); ?></p>
			<p class="cd-la-summary" data-pi-changes></p>
			<h3 class="cd-la-subheading" id="cd-pi-diff-title"><?php esc_html_e( 'Changes: before and after', 'cyberdat' ); ?></h3>
			<p class="cd-la-help" id="cd-pi-diff-help"><?php esc_html_e( 'Removed text is struck through, inserted text is underlined. Each change starts with “−” (removed) and “+” (inserted) for screen readers and high-contrast modes.', 'cyberdat' ); ?></p>
			<pre class="cd-la-preview cd-pi-diff" tabindex="0" role="region" aria-labelledby="cd-pi-diff-title" aria-describedby="cd-pi-diff-help" data-pi-diff></pre>
			<p class="cd-la-help" data-pi-diff-truncated hidden></p>
			<div class="cd-la-row">
				<button type="button" class="cd-la-button cd-la-button--primary" data-pi-copy><?php esc_html_e( 'Copy sanitized copy', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--secondary" data-pi-download><?php esc_html_e( 'Download sanitized copy', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--secondary" data-pi-report><?php esc_html_e( 'Download findings (JSON)', 'cyberdat' ); ?></button>
			</div>
			<p class="cd-la-help"><?php esc_html_e( 'The findings report contains short excerpts of your text. It is created in your browser and saved only where you choose.', 'cyberdat' ); ?></p>
		</section>
	</div>

	<div class="cd-la-info">
		<section aria-labelledby="cd-pi-how">
			<h2 id="cd-pi-how"><?php esc_html_e( 'How it works', 'cyberdat' ); ?></h2>
			<ol>
				<li><?php esc_html_e( 'Your text or file is read by a background worker inside this browser tab, so large inputs do not freeze the page.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'A normalized copy is built first: zero-width, tag, variation-selector and bidirectional control characters are removed and Unicode NFKC is applied. Base64, hex, URL-encoded and escaped fragments are decoded up to three layers deep. Every position is mapped back to your original text.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Versioned rules look for known injection techniques in seven groups:', 'cyberdat' ); ?>
					<ul class="cd-pi-groups-list">
						<?php foreach ( $cyberdat_pi['groups'] as $cyberdat_pi_group ) : ?>
							<li><strong><?php echo esc_html( $cyberdat_pi_group['label'] ); ?></strong> — <?php echo esc_html( $cyberdat_pi_group['example'] ); ?></li>
						<?php endforeach; ?>
					</ul>
				</li>
				<li><?php esc_html_e( 'Every finding has a rule id, a severity, its line and column and an explanation. Phrases that are quoted or given as examples ("phrases like …") are still reported, with low severity.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'The sanitized copy is secondary: it removes invisible characters, applies NFKC and replaces flagged passages with a visible marker, and every change is listed so you can check it.', 'cyberdat' ); ?></li>
			</ol>
			<p class="cd-la-meta"><?php printf( esc_html__( 'Engine %1$s · rules %2$s', 'cyberdat' ), esc_html( $cyberdat_pi['engine_version'] ), esc_html( $cyberdat_pi['ruleset'] ) ); ?></p>
		</section>
		<section aria-labelledby="cd-pi-privacy">
			<h2 id="cd-pi-privacy"><?php esc_html_e( 'Privacy', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'The text you enter is never sent anywhere. The page has no server endpoint for your data, it does not call any AI model or external service, and its Content Security Policy blocks scripts on this page from opening network connections.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'If you select Cancel (or processing times out), the background worker is restarted and the browser downloads its two static script files again from this site. Those requests contain no part of your input.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Nothing is saved: input, findings and settings are not written to cookies, local storage or the address bar, and they disappear when you close or reload the tab.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'The text is treated as data only: it is never executed, and it is displayed as plain text, never as HTML, so markup or scripts in it cannot run.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Browser extensions you have installed can read page content. Use a private window without extensions for confidential documents.', 'cyberdat' ); ?></li>
			</ul>
		</section>
		<section aria-labelledby="cd-pi-limits">
			<h2 id="cd-pi-limits"><?php esc_html_e( 'Limitations of automated analysis', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'Detection is rule-based. Attacks written in new words, spread across several sentences or in other languages are not detected. Rules cover English, German and Russian; French and Spanish only for the most common override phrase. No rule set can recognize every prompt injection.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Some legitimate texts are flagged, for example security articles that quote attack phrases, documentation of chat templates or hidden menus in HTML. Quoted phrases get low severity, but quoting does not make an instruction harmless to a model.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Hidden text is found only in the HTML source: CSS classes defined in style sheets, images, PDF layers and text extracted by OCR are not analyzed. Paste the text extracted from a PDF; the file itself is not read.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Decoding covers Base64, hex, URL encoding and HTML/Unicode escapes. ROT13, ciphers, compression and instructions split across several fragments are not decoded.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'NFKC normalization and character removal can change the meaning of mathematical symbols, ligatures or right-to-left text in the sanitized copy. Check the list of changes.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Large inputs (above about 10 MB) can take a long time, especially in Safari and other WebKit browsers. The limit is 20 MB.', 'cyberdat' ); ?></li>
			</ul>
		</section>
	</div>
</div>
