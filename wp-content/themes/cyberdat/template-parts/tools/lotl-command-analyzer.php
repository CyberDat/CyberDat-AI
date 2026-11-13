<?php
/* Copyright (C) 2026 CyberDat contributors; SPDX-License-Identifier: GPL-3.0-only. Modified 2026-11-13: GPL notices/source delivery. No warranty; see assets/js/lotl-analyzer/LICENSE-LOLBAS.txt. */
/**
 * LotL / LOLBAS Command Analyzer — interactive workspace markup.
 * Static, server-rendered UI only. Command lines are analyzed in the browser by
 * assets/js/lotl-analyzer/*.js as text; they are never executed and never posted to WordPress.
 * Shared .cd-la-* component classes come from assets/css/tools-common.css.
 */
defined( 'ABSPATH' ) || exit;
$cyberdat_lotl = cyberdat_lotl_config();
$cyberdat_lotl_commit = $cyberdat_lotl['data']['commit'];
?>
<div class="cd-la cd-lotl" data-lotl-analyzer data-worker-src="<?php echo esc_url( $cyberdat_lotl['worker'] ); ?>">
	<noscript><p class="cd-la-callout cd-la-callout--warning"><?php esc_html_e( 'This tool needs JavaScript. Analysis happens only in your browser, so nothing can run without it — and nothing is uploaded.', 'cyberdat' ); ?></p></noscript>
	<p class="cd-la-callout cd-la-callout--error" data-lotl-unsupported hidden><?php esc_html_e( 'Your browser does not support the background processing this tool needs (Web Workers). Try a current version of Edge, Chrome, Firefox or Safari.', 'cyberdat' ); ?></p>

	<div class="cd-la-app" data-lotl-app hidden>
		<p class="cd-la-callout cd-la-callout--privacy"><strong><?php esc_html_e( 'Local only.', 'cyberdat' ); ?></strong> <?php esc_html_e( 'Commands are analyzed in this browser tab as plain text. This tool does not transmit the text you enter — not to CyberDat, not to analytics, not to GitHub — it is never executed, and this tool does not write it to persistent browser storage.', 'cyberdat' ); ?></p>
		<p class="cd-la-callout cd-la-callout--warning" role="note"><strong><?php esc_html_e( 'A match is not a verdict.', 'cyberdat' ); ?></strong> <?php esc_html_e( 'Most binaries listed in LOLBAS are legitimate Windows components used every day. A match only means the command resembles a documented abuse technique; no match does not mean the command is safe.', 'cyberdat' ); ?></p>

		<section class="cd-la-panel" aria-labelledby="cd-lotl-step-input">
			<h2 id="cd-lotl-step-input" class="cd-la-step"><span aria-hidden="true">1</span> <?php esc_html_e( 'Add command lines', 'cyberdat' ); ?></h2>
			<label class="cd-la-label" for="cd-lotl-input"><?php esc_html_e( 'Command lines, one per line', 'cyberdat' ); ?></label>
			<textarea id="cd-lotl-input" class="cd-la-input" rows="10" spellcheck="false" autocomplete="off" autocapitalize="off" autocorrect="off" data-gramm="false" data-gramm_editor="false" data-enable-grammarly="false" data-lt-active="false" aria-describedby="cd-lotl-input-help cd-lotl-source" data-lotl-input></textarea>
			<p id="cd-lotl-input-help" class="cd-la-help"><?php esc_html_e( 'Paste process command lines from an alert, EDR or Sysmon event. Log records with a CommandLine field (JSON or key: value) are recognized and the field is extracted. You can also load a text, CSV or JSON export (UTF-8 or UTF-16 with BOM, up to 5 MB).', 'cyberdat' ); ?></p>
			<div class="cd-la-row">
				<label class="cd-la-file">
					<span class="cd-la-button cd-la-button--secondary" aria-hidden="true"><?php esc_html_e( 'Load a text file', 'cyberdat' ); ?></span>
					<input class="cd-la-file__input" id="cd-lotl-file" type="file" accept=".txt,.text,.log,.csv,.tsv,.json,.jsonl,.ndjson,.xml,text/plain,application/json" aria-label="<?php esc_attr_e( 'Load a text file', 'cyberdat' ); ?>" data-lotl-file>
				</label>
				<button type="button" class="cd-la-button cd-la-button--secondary" data-lotl-sample><?php esc_html_e( 'Load examples', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--ghost" data-lotl-clear><?php esc_html_e( 'Clear everything', 'cyberdat' ); ?></button>
			</div>
			<p id="cd-lotl-source" class="cd-la-source" aria-live="polite" data-lotl-source></p>
		</section>

		<div class="cd-la-actions">
			<button type="button" class="cd-la-button cd-la-button--primary" data-lotl-run><?php esc_html_e( 'Analyze commands', 'cyberdat' ); ?></button>
			<button type="button" class="cd-la-button cd-la-button--ghost" data-lotl-cancel hidden><?php esc_html_e( 'Cancel', 'cyberdat' ); ?></button>
			<progress class="cd-la-progress" max="100" value="0" aria-label="<?php esc_attr_e( 'Analysis progress', 'cyberdat' ); ?>" data-lotl-progress hidden></progress>
		</div>
		<p class="cd-la-status" role="status" aria-live="polite" data-lotl-status></p>
		<div class="cd-la-callout cd-la-callout--error" role="alert" data-lotl-error hidden></div>

		<section class="cd-la-panel cd-la-results" aria-labelledby="cd-lotl-step-results" data-lotl-results hidden>
			<h2 id="cd-lotl-step-results" class="cd-la-step" tabindex="-1"><span aria-hidden="true">2</span> <?php esc_html_e( 'Review the analysis', 'cyberdat' ); ?></h2>
			<p class="cd-lotl-verdict" data-lotl-verdict></p>
			<p class="cd-la-summary" data-lotl-summary></p>
			<div class="cd-la-table-wrap" data-lotl-categories-wrap hidden>
				<table class="cd-la-table">
					<caption><?php esc_html_e( 'Documented LOLBAS functions matched', 'cyberdat' ); ?></caption>
					<thead><tr><th scope="col"><?php esc_html_e( 'LOLBAS function', 'cyberdat' ); ?></th><th scope="col"><?php esc_html_e( 'Matches', 'cyberdat' ); ?></th></tr></thead>
					<tbody data-lotl-categories></tbody>
				</table>
			</div>
			<h3 class="cd-la-subheading" id="cd-lotl-commands-title"><?php esc_html_e( 'Commands', 'cyberdat' ); ?></h3>
			<p class="cd-la-help"><?php esc_html_e( 'Sorted by severity. “From LOLBAS” marks information taken from the LOLBAS Project data; “CyberDat heuristic” marks checks written for this tool.', 'cyberdat' ); ?></p>
			<ol class="cd-lotl-commands" aria-labelledby="cd-lotl-commands-title" data-lotl-commands></ol>
			<p class="cd-la-help" data-lotl-more hidden></p>
			<div class="cd-la-row">
				<button type="button" class="cd-la-button cd-la-button--secondary" data-lotl-report><?php esc_html_e( 'Download analysis (JSON)', 'cyberdat' ); ?></button>
			</div>
			<p class="cd-la-help"><?php esc_html_e( 'The report contains your command lines. It is created in your browser and saved only where you choose.', 'cyberdat' ); ?></p>
		</section>
	</div>

	<div class="cd-la-info">
		<section aria-labelledby="cd-lotl-how">
			<h2 id="cd-lotl-how"><?php esc_html_e( 'How it works', 'cyberdat' ); ?></h2>
			<ol>
				<li><?php esc_html_e( 'Each line is analyzed as text in a background worker. If the line is a log record, its CommandLine field is used.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Simple obfuscation is undone statically: cmd.exe ^ escapes, quotes inside words, PowerShell backticks, look-alike dashes and letter case. PowerShell -EncodedCommand values (Base64 of UTF-16LE) and FromBase64String literals are decoded and analyzed too. Nothing is executed or evaluated.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Binaries, scripts and libraries are looked up in a bundled snapshot of the LOLBAS Project. The command is compared with every documented LOLBAS usage of that binary by its flags and arguments.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'For each match the tool shows the LOLBAS function (for example Download, Execute, AWL Bypass), the description, the MITRE ATT&CK® technique id exactly as given in LOLBAS, and the LOLBAS detection hints. No technique mapping is added by CyberDat.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Separate CyberDat heuristics point out encoded PowerShell, download patterns, obfuscation, unusual binary locations and similar signals. They have no ATT&CK mapping and are not detection rules.', 'cyberdat' ); ?></li>
			</ol>
			<p class="cd-la-meta"><?php printf( esc_html__( 'Engine %1$s · heuristics %2$s · LOLBAS data %3$s (%4$s)', 'cyberdat' ), esc_html( $cyberdat_lotl['engine_version'] ), esc_html( $cyberdat_lotl['ruleset'] ), esc_html( substr( $cyberdat_lotl_commit, 0, 12 ) ), esc_html( $cyberdat_lotl['data']['date'] ) ); ?></p>
		</section>
		<section aria-labelledby="cd-lotl-source-title">
			<h2 id="cd-lotl-source-title"><?php esc_html_e( 'Data source and license', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'Windows binary data comes from the LOLBAS Project (Living Off The Land Binaries, Scripts and Libraries), maintained by its contributors:', 'cyberdat' ); ?> <a href="https://github.com/LOLBAS-Project/LOLBAS" rel="noopener noreferrer">github.com/LOLBAS-Project/LOLBAS</a>. <?php printf( esc_html__( 'Snapshot of commit %1$s from %2$s.', 'cyberdat' ), esc_html( $cyberdat_lotl_commit ), esc_html( $cyberdat_lotl['data']['date'] ) ); ?></li>
				<li><?php esc_html_e( 'The LOLBAS data is licensed under the GNU General Public License v3.0. This page uses a modified version: converted from YAML to JSON with a subset of fields (author, acknowledgement and resource links omitted).', 'cyberdat' ); ?> <a href="<?php echo esc_url( $cyberdat_lotl['license_url'] ); ?>"><?php esc_html_e( 'License text (GPL-3.0)', 'cyberdat' ); ?></a>. <?php esc_html_e( 'The LotL app, engine, worker, modified data and tool-specific renderer/CSS are provided under GPL version 3, without warranty. You may redistribute and modify them under that license.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'MITRE ATT&CK® technique ids are shown as provided by LOLBAS. ATT&CK® is a registered trademark of The MITRE Corporation. “© 2021 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.” (notice as reproduced in the LOLBAS NOTICE file)', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Links to LOLBAS pages and detection references are ordinary links; nothing is loaded from them automatically. Microsoft® Windows® is a registered trademark of Microsoft Corporation.', 'cyberdat' ); ?></li>
			</ul>
		</section>
		<p><a href="<?php echo esc_url( $cyberdat_lotl['source_url'] ); ?>" rel="noopener noreferrer"><?php esc_html_e( 'Corresponding source: complete theme and LotL code', 'cyberdat' ); ?></a> · <a href="<?php echo esc_url( $cyberdat_lotl['upstream_source_url'] ); ?>" rel="noopener noreferrer"><?php esc_html_e( 'Pinned upstream YAML source archive', 'cyberdat' ); ?></a> · <a href="<?php echo esc_url( $cyberdat_lotl['notice_url'] ); ?>"><?php esc_html_e( 'Original LOLBAS and MITRE notices', 'cyberdat' ); ?></a></p>
<section aria-labelledby="cd-lotl-privacy">
			<h2 id="cd-lotl-privacy"><?php esc_html_e( 'Privacy', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'This tool does not transmit the text you enter. The LOLBAS data is part of this page, so no request is made to GitHub or any other service, and the page’s Content Security Policy blocks scripts on this page from opening network connections.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'If you select Cancel (or processing times out), the background worker is restarted and the browser downloads its static script files again from this site. Those requests contain no part of your input.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'This tool does not persist data: input and results are not written to cookies, local storage or the address bar, and the tool resets them when you close or reload the tab. Browser session restore, extensions, the clipboard and downloaded files are outside these controls; this is not secure erasure.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Commands are treated as data only: they are never executed, and they are displayed as plain text, never as HTML.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Browser extensions you have installed can read page content. Use a private window without extensions for sensitive incident data.', 'cyberdat' ); ?></li>
			</ul>
		</section>
		<section aria-labelledby="cd-lotl-limits">
			<h2 id="cd-lotl-limits"><?php esc_html_e( 'Limitations of automated analysis', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'Only Windows binaries documented in LOLBAS are recognized. Linux and macOS commands are not covered, and abuse techniques that LOLBAS does not document are only caught by the generic heuristics, if at all.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Renamed or copied binaries are recognized only by name; the command line alone cannot show what file actually ran. Check the process image, hash and parent process.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Deobfuscation is static and limited: environment-variable substrings, string concatenation, compression, nested encodings beyond two levels and script files referenced by the command are not resolved.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Matching is based on flags and arguments in the documented LOLBAS commands. Unusual argument orders or abbreviations may be missed, and ordinary administrative commands can partially match a documented usage.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Detection hints and references are the ones listed in LOLBAS. LOLBAS states that they do not guarantee detection; they are starting points for an investigation, not rules.', 'cyberdat' ); ?></li>
			</ul>
		</section>
	</div>
</div>
