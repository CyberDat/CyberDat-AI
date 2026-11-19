<?php
/**
 * Email Header Analyzer — interactive workspace markup.
 * Static, server-rendered UI only. Headers are analysed in the browser by assets/js/email-header-analyzer/*.js; the
 * message body is ignored; nothing is looked up online or posted to WordPress.
 * Inputs and results carry translate="no" and the notranslate class.
 */
defined( 'ABSPATH' ) || exit;
$cyberdat_eha = cyberdat_eha_config();
$cyberdat_eha_ta = 'class="cd-la-input notranslate" translate="no" spellcheck="false" autocomplete="off" autocapitalize="off" autocorrect="off" data-gramm="false" data-gramm_editor="false" data-enable-grammarly="false" data-lt-active="false"';
?>
<div class="cd-la cd-eha" data-eha data-worker-state="loading" data-worker-src="<?php echo esc_url( $cyberdat_eha['worker'] ); ?>">
	<noscript><p class="cd-la-callout cd-la-callout--warning"><?php esc_html_e( 'This tool needs JavaScript. Everything happens only in your browser, so nothing can run without it — and nothing is uploaded.', 'cyberdat' ); ?></p></noscript>
	<p class="cd-la-callout cd-la-callout--error" data-eha-unsupported hidden><?php esc_html_e( 'Your browser does not support the background processing this tool needs (Web Workers). Try a current version of Edge, Chrome, Firefox or Safari.', 'cyberdat' ); ?></p>

	<div class="cd-la-app" data-eha-app hidden>
		<p class="cd-la-callout cd-la-callout--privacy"><strong><?php esc_html_e( 'Local only.', 'cyberdat' ); ?></strong> <?php esc_html_e( 'Your text is analyzed in this browser tab. This tool does not transmit the text you enter — not to CyberDat, not to analytics, not to any mail, DNS or reputation service — and this tool does not write it to persistent browser storage.', 'cyberdat' ); ?></p>
		<p class="cd-la-callout cd-la-callout--warning" role="note"><strong><?php esc_html_e( 'Headers only, no lookups.', 'cyberdat' ); ?></strong> <?php esc_html_e( 'The tool reads what the mail servers recorded. It makes no DNS, WHOIS or reputation lookups and does not verify DKIM signatures. The message body and attachments are ignored. A message without findings is not shown to be safe or genuine.', 'cyberdat' ); ?></p>
		<p class="cd-eha-state" role="status" aria-live="polite" data-eha-worker-status><?php esc_html_e( 'Starting the local analyzer…', 'cyberdat' ); ?></p>

		<section class="cd-la-panel" aria-labelledby="cd-eha-step-input">
			<h2 id="cd-eha-step-input" class="cd-la-step"><span aria-hidden="true">1</span> <?php esc_html_e( 'Add the message headers', 'cyberdat' ); ?></h2>
			<label class="cd-la-label" for="cd-eha-input"><?php esc_html_e( 'Message headers or the whole message source', 'cyberdat' ); ?></label>
			<textarea id="cd-eha-input" <?php echo $cyberdat_eha_ta; // phpcs:ignore WordPress.Security.EscapeOutput -- static attribute string ?> rows="16" aria-describedby="cd-eha-input-help cd-eha-size" data-eha-input></textarea>
			<p id="cd-eha-input-help" class="cd-la-help"><?php esc_html_e( 'Gmail: open the message, More, Show original. Outlook: File, Properties, Internet headers (desktop) or View, View message source (web). Only the part before the first empty line is analysed; the body is ignored. Up to 5 MB.', 'cyberdat' ); ?></p>
			<p id="cd-eha-size" class="cd-la-source" aria-live="polite" data-eha-size></p>
			<label class="cd-la-label" for="cd-eha-file"><?php esc_html_e( 'Or open a saved message (.eml or .txt)', 'cyberdat' ); ?></label>
			<input id="cd-eha-file" class="cd-eha-file notranslate" translate="no" type="file" accept=".eml,.txt,message/rfc822,text/plain" data-eha-file>
			<label class="cd-la-label" for="cd-eha-own"><?php esc_html_e( 'Your domain or mail server names (optional)', 'cyberdat' ); ?></label>
			<input id="cd-eha-own" class="cd-la-text cd-eha-own notranslate" translate="no" type="text" spellcheck="false" autocomplete="off" autocapitalize="off" aria-describedby="cd-eha-own-help" data-eha-own>
			<p id="cd-eha-own-help" class="cd-la-help"><?php esc_html_e( 'For example example.com, gateway.example.net. Servers of these domains are treated as yours, which sets the trust boundary more precisely. Lookalikes of these domains are reported.', 'cyberdat' ); ?></p>
			<div class="cd-la-row">
				<button type="button" class="cd-la-button cd-la-button--secondary" data-eha-sample="phishing"><?php esc_html_e( 'Load phishing example', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--secondary" data-eha-sample="normal"><?php esc_html_e( 'Load normal example', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--ghost" data-eha-clear><?php esc_html_e( 'Clear', 'cyberdat' ); ?></button>
			</div>
		</section>

		<div class="cd-la-actions">
			<button type="button" class="cd-la-button cd-la-button--primary" data-eha-run><?php esc_html_e( 'Analyze headers', 'cyberdat' ); ?></button>
			<button type="button" class="cd-la-button cd-la-button--ghost" data-eha-cancel hidden><?php esc_html_e( 'Cancel', 'cyberdat' ); ?></button>
			<progress class="cd-la-progress" max="100" value="0" aria-label="<?php esc_attr_e( 'Progress', 'cyberdat' ); ?>" data-eha-progress hidden></progress>
		</div>
		<p class="cd-la-status" role="status" aria-live="polite" data-eha-status></p>
		<div class="cd-la-callout cd-la-callout--error notranslate" translate="no" role="alert" data-eha-error hidden></div>

		<section class="cd-la-panel cd-la-results notranslate" translate="no" aria-labelledby="cd-eha-step-results" data-eha-results hidden>
			<h2 id="cd-eha-step-results" class="cd-la-step" tabindex="-1"><span aria-hidden="true">2</span> <b class="cd-eha-step-title"><?php esc_html_e( 'Review the analysis', 'cyberdat' ); ?></b></h2>
			<p class="cd-eha-verdict" data-eha-verdict></p>
			<ul class="cd-eha-notes" data-eha-notes hidden></ul>
			<h3 class="cd-la-subheading"><?php esc_html_e( 'Message', 'cyberdat' ); ?></h3>
			<dl class="cd-eha-summary" data-eha-summary></dl>
			<h3 class="cd-la-subheading"><?php esc_html_e( 'Findings', 'cyberdat' ); ?></h3>
			<ol class="cd-eha-findings" data-eha-findings></ol>
			<details class="cd-eha-more" data-eha-info-wrap hidden>
				<summary data-eha-info-title></summary>
				<ol class="cd-eha-findings" data-eha-info></ol>
			</details>
			<h3 class="cd-la-subheading"><?php esc_html_e( 'Delivery path, from sender to you', 'cyberdat' ); ?></h3>
			<p class="cd-la-help" data-eha-boundary></p>
			<ol class="cd-eha-path" data-eha-path></ol>
			<h3 class="cd-la-subheading"><?php esc_html_e( 'Authentication', 'cyberdat' ); ?></h3>
			<ul class="cd-eha-auth" data-eha-auth></ul>
			<p class="cd-eha-align" data-eha-align></p>
			<h3 class="cd-la-subheading"><?php esc_html_e( 'Export', 'cyberdat' ); ?></h3>
			<label class="cd-la-check"><input type="checkbox" data-eha-mask="recipients"> <span><?php esc_html_e( 'Mask recipient addresses', 'cyberdat' ); ?></span></label>
			<label class="cd-la-check"><input type="checkbox" data-eha-mask="internal"> <span><?php esc_html_e( 'Mask internal IP addresses', 'cyberdat' ); ?></span></label>
			<div class="cd-la-row">
				<button type="button" class="cd-la-button cd-la-button--secondary" data-eha-report="markdown"><?php esc_html_e( 'Download report (Markdown)', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--secondary" data-eha-report="json"><?php esc_html_e( 'Download report (JSON)', 'cyberdat' ); ?></button>
			</div>
			<p class="cd-la-help"><?php esc_html_e( 'The report contains the findings, the parsed path and the authentication results; values that look like secrets are always masked. It never contains the message body. Choose the masking options before sharing it with colleagues.', 'cyberdat' ); ?></p>
		</section>
	</div>

	<div class="cd-la-info">
		<section aria-labelledby="cd-eha-how">
			<h2 id="cd-eha-how"><?php esc_html_e( 'How it works', 'cyberdat' ); ?></h2>
			<ol>
				<li><?php esc_html_e( 'Only the header block is read: long headers folded over several lines are joined, encoded names and subjects (such as =?UTF-8?B?…?=) are decoded with the browser’s built-in text decoder, and CRLF or LF line endings and extra spaces copied from webmail are handled.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Received lines are read from the bottom (sender) to the top (you): from, by, with, id, for, IP address and time, with the delay at each step. Formats from Gmail, Microsoft 365 and Exchange, Postfix, Exim, Sendmail and common gateways are recognised; a line that is not recognised is shown as written.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Trust boundary: the top lines are added by your own mail servers and can be believed. Everything below the first external server could have been written by the sender. The tool marks the assumed boundary; enter your domain or server names to set it more precisely.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Authentication-Results, ARC-Authentication-Results, Received-SPF and DKIM-Signature are read. SPF, DKIM, DMARC and ARC results are shown with the server that recorded them; results below the boundary or from an unknown server are marked as not trusted. Alignment compares the From domain with the SPF and DKIM domains using organizational domains from the Public Suffix List.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'CyberDat rules then look for display names that name another address or a brand, Reply-To and Return-Path on other domains, lookalike domains (punycode, mixed alphabets, similar letters, digits for letters) compared with a short CyberDat brand list and with your own domain, missing or unusual Date and Message-ID, and mail software, originating IP and bulk-mail headers as information.', 'cyberdat' ); ?></li>
			</ol>
			<p class="cd-la-meta"><?php printf( esc_html__( 'Engine %1$s · rules %2$s · Public Suffix List %3$s', 'cyberdat' ), esc_html( $cyberdat_eha['engine_version'] ), esc_html( $cyberdat_eha['ruleset'] ), esc_html( $cyberdat_eha['psl_date'] ) ); ?></p>
		</section>
		<section aria-labelledby="cd-eha-privacy">
			<h2 id="cd-eha-privacy"><?php esc_html_e( 'Privacy', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'This tool does not transmit the text you enter. The page has no server endpoint for your data, and its Content Security Policy blocks scripts on this page from opening network connections. Internal IP addresses, addresses and server names in your headers stay in this tab.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Input fields and results are marked so that the browser’s built-in page translator does not translate them, because translating would send their text to a translation service.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'If you select Cancel (or processing times out), the background worker is restarted and the browser downloads its static script files again from this site. Those requests contain no part of your input.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'This tool does not persist data: input, findings and settings are not written to cookies, local storage or the address bar, and the tool resets them when you close or reload the tab. Browser session restore, extensions, the clipboard and downloaded files are outside these controls; this is not secure erasure.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Values that look like secrets are shown masked in results and reports; masking is best effort.', 'cyberdat' ); ?></li>
			</ul>
		</section>
		<section aria-labelledby="cd-eha-limits">
			<h2 id="cd-eha-limits"><?php esc_html_e( 'Limitations', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'No network lookups: the tool does not query DNS (SPF, DKIM, DMARC or MX records), WHOIS or the reputation of IP addresses and domains, and it does not verify DKIM signatures cryptographically. It shows the results the receiving servers already recorded.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'A message is never shown to be safe or genuine. A hijacked real account, or a message sent through a legitimate service, passes every check.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'The trust boundary is an estimate from server names. Gateways or forwarders run by another company are treated as external until you enter them as your own. A forged result written just below your server’s own line can only be recognised when your server also wrote one above it.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'The body, links and attachments are not analysed. The brand list is short and written by CyberDat; lookalike detection compares spelling only and misses lookalikes of other names.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Unusual Received formats may not be recognised. Organizational domains follow the bundled Public Suffix List snapshot; newer suffixes are unknown until the list is updated.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Input up to 5 MB, header part up to 1 MB. Processing stops after 30 seconds.', 'cyberdat' ); ?></li>
			</ul>
		</section>
		<section aria-labelledby="cd-eha-sources">
			<h2 id="cd-eha-sources"><?php esc_html_e( 'Sources', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'All rules, explanations, the brand list and the examples are written by CyberDat.', 'cyberdat' ); ?></li>
				<li><?php printf( esc_html__( 'Public Suffix List by the Public Suffix List project, Mozilla Public License 2.0, snapshot of commit %1$s (%2$s). It is published unmodified with this tool as public_suffix_list.dat together with its license text (LICENSE-MPL-2.0.txt).', 'cyberdat' ), esc_html( substr( $cyberdat_eha['psl_commit'], 0, 12 ) ), esc_html( $cyberdat_eha['psl_date'] ) ); ?></li>
				<li><?php esc_html_e( 'Background reading: the IETF standards for message format, Received lines, Authentication-Results, SPF, DKIM, DMARC and ARC. They are referenced here by name only; no text is copied.', 'cyberdat' ); ?></li>
			</ul>
		</section>
	</div>
</div>
