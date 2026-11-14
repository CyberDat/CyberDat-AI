<?php
/**
 * MCP Security & Policy Checker — interactive workspace markup.
 * Static, server-rendered UI only. Configurations, tool lists and policies are checked in the browser by
 * assets/js/mcp-checker/*.js as text; servers are never started, commands never run, URLs never requested,
 * and nothing is posted to WordPress. Shared .cd-la-* component classes come from assets/css/tools-common.css.
 */
defined( 'ABSPATH' ) || exit;
$cyberdat_mcp = cyberdat_mcp_config();
?>
<div class="cd-la cd-mcp" data-mcp-checker data-worker-src="<?php echo esc_url( $cyberdat_mcp['worker'] ); ?>">
	<noscript><p class="cd-la-callout cd-la-callout--warning"><?php esc_html_e( 'This tool needs JavaScript. The check happens only in your browser, so nothing can run without it — and nothing is uploaded.', 'cyberdat' ); ?></p></noscript>
	<p class="cd-la-callout cd-la-callout--error" data-mcp-unsupported hidden><?php esc_html_e( 'Your browser does not support the background processing this tool needs (Web Workers). Try a current version of Edge, Chrome, Firefox or Safari.', 'cyberdat' ); ?></p>

	<div class="cd-la-app" data-mcp-app hidden>
		<p class="cd-la-callout cd-la-callout--privacy"><strong><?php esc_html_e( 'Local only.', 'cyberdat' ); ?></strong> <?php esc_html_e( 'The configuration is checked in this browser tab as text. This tool does not transmit the text you enter — not to CyberDat, not to analytics, not to any registry — servers are not started, and this tool does not write it to persistent browser storage.', 'cyberdat' ); ?></p>
		<p class="cd-la-callout cd-la-callout--warning" role="note"><strong><?php esc_html_e( 'A review aid, not a guarantee.', 'cyberdat' ); ?></strong> <?php esc_html_e( 'Findings are based only on the text you paste. A finding is a reason to look closer, not proof of an attack, and no finding does not mean the configuration is safe.', 'cyberdat' ); ?></p>

		<section class="cd-la-panel" aria-labelledby="cd-mcp-step-input">
			<h2 id="cd-mcp-step-input" class="cd-la-step"><span aria-hidden="true">1</span> <?php esc_html_e( 'Add a configuration or tool list', 'cyberdat' ); ?></h2>
			<label class="cd-la-label" for="cd-mcp-input"><?php esc_html_e( 'MCP configuration or tool list (JSON)', 'cyberdat' ); ?></label>
			<textarea id="cd-mcp-input" class="cd-la-input" rows="14" spellcheck="false" autocomplete="off" autocapitalize="off" autocorrect="off" data-gramm="false" data-gramm_editor="false" data-enable-grammarly="false" data-lt-active="false" aria-describedby="cd-mcp-input-help cd-mcp-source" data-mcp-input></textarea>
			<p id="cd-mcp-input-help" class="cd-la-help"><?php esc_html_e( 'Accepted: client configurations with "mcpServers", "servers" or "mcp.servers" (command, args, env, url, headers), "context_servers", a single server object, and tool lists ({"tools": [...]} or a tools/list response) with names, descriptions and input schemas. Comments and trailing commas are accepted. Several JSON documents can be pasted one after another. Up to 5 MB.', 'cyberdat' ); ?></p>
			<div class="cd-la-row">
				<label class="cd-la-file">
					<span class="cd-la-button cd-la-button--secondary" aria-hidden="true"><?php esc_html_e( 'Load a JSON file', 'cyberdat' ); ?></span>
					<input class="cd-la-file__input" id="cd-mcp-file" type="file" accept=".json,.jsonc,.txt,application/json,text/plain" aria-label="<?php esc_attr_e( 'Load a JSON file', 'cyberdat' ); ?>" data-mcp-file>
				</label>
				<button type="button" class="cd-la-button cd-la-button--secondary" data-mcp-sample><?php esc_html_e( 'Load example', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--ghost" data-mcp-clear><?php esc_html_e( 'Clear everything', 'cyberdat' ); ?></button>
			</div>
			<p id="cd-mcp-source" class="cd-la-source" aria-live="polite" data-mcp-source></p>

			<fieldset class="cd-mcp-modes">
				<legend class="cd-la-label"><?php esc_html_e( 'What to check', 'cyberdat' ); ?></legend>
				<label class="cd-mcp-mode"><input type="radio" name="cd-mcp-mode" value="security" checked data-mcp-mode> <span><strong><?php esc_html_e( 'Security check', 'cyberdat' ); ?></strong> — <?php esc_html_e( 'look for risky settings, secrets and suspicious tool descriptions', 'cyberdat' ); ?></span></label>
				<label class="cd-mcp-mode"><input type="radio" name="cd-mcp-mode" value="policy" data-mcp-mode> <span><strong><?php esc_html_e( 'Policy check', 'cyberdat' ); ?></strong> — <?php esc_html_e( 'compare the configuration with your own rules', 'cyberdat' ); ?></span></label>
			</fieldset>

			<div class="cd-mcp-policy" data-mcp-policy-panel hidden>
				<label class="cd-la-label" for="cd-mcp-policy"><?php esc_html_e( 'Your policy (JSON)', 'cyberdat' ); ?></label>
				<textarea id="cd-mcp-policy" class="cd-la-input" rows="12" spellcheck="false" autocomplete="off" autocapitalize="off" autocorrect="off" data-gramm="false" data-gramm_editor="false" data-enable-grammarly="false" data-lt-active="false" aria-describedby="cd-mcp-policy-help cd-mcp-policy-source" data-mcp-policy></textarea>
				<p id="cd-mcp-policy-help" class="cd-la-help"><?php esc_html_e( 'The policy is kept only in this tab. “Download policy” saves the entered policy without redaction; review it for private values before sharing.', 'cyberdat' ); ?></p>
				<div class="cd-la-row">
					<label class="cd-la-file">
						<span class="cd-la-button cd-la-button--secondary" aria-hidden="true"><?php esc_html_e( 'Load a policy file', 'cyberdat' ); ?></span>
						<input class="cd-la-file__input" id="cd-mcp-policy-file" type="file" accept=".json,.jsonc,.txt,application/json,text/plain" aria-label="<?php esc_attr_e( 'Load a policy file', 'cyberdat' ); ?>" data-mcp-policy-file>
					</label>
					<button type="button" class="cd-la-button cd-la-button--secondary" data-mcp-policy-example><?php esc_html_e( 'Load example policy', 'cyberdat' ); ?></button>
					<button type="button" class="cd-la-button cd-la-button--ghost" data-mcp-policy-download><?php esc_html_e( 'Download policy', 'cyberdat' ); ?></button>
				</div>
				<p id="cd-mcp-policy-source" class="cd-la-source" aria-live="polite" data-mcp-policy-source></p>
				<details class="cd-mcp-schema">
					<summary><?php esc_html_e( 'Policy settings', 'cyberdat' ); ?></summary>
					<p class="cd-la-help"><?php esc_html_e( 'All settings are optional. Lists accept * and ? wildcards (not in paths). Denied entries always take precedence over allowed ones.', 'cyberdat' ); ?></p>
					<dl class="cd-mcp-dl">
						<dt><code>version</code></dt><dd><?php esc_html_e( 'Must be 1.', 'cyberdat' ); ?></dd>
						<dt><code>allowedCommands</code>, <code>deniedCommands</code></dt><dd><?php esc_html_e( 'Executables that start servers, by name (npx, uvx, docker, node …), including commands wrapped in sudo or a shell.', 'cyberdat' ); ?></dd>
						<dt><code>allowedPackages</code>, <code>deniedPackages</code></dt><dd><?php esc_html_e( 'npm and Python package names and container image names.', 'cyberdat' ); ?></dd>
						<dt><code>requirePinnedVersions</code></dt><dd><?php esc_html_e( 'true: every package and image needs an exact version or digest.', 'cyberdat' ); ?></dd>
						<dt><code>allowedHosts</code>, <code>deniedHosts</code></dt><dd><?php esc_html_e( 'Host names of remote servers and of http(s) URLs in arguments. *.example.com matches subdomains only.', 'cyberdat' ); ?></dd>
						<dt><code>requireHttps</code></dt><dd><?php esc_html_e( 'true: remote servers must use https:// (localhost is exempt).', 'cyberdat' ); ?></dd>
						<dt><code>allowedPaths</code>, <code>deniedPaths</code></dt><dd><?php esc_html_e( 'Directories. A path is allowed when it is inside an allowed directory; it violates a denied path when it is inside it or contains it. ~ also matches /home/<name>, /Users/<name> and C:\Users\<name>.', 'cyberdat' ); ?></dd>
						<dt><code>allowedTransports</code></dt><dd><?php esc_html_e( 'Any of "stdio", "http", "sse".', 'cyberdat' ); ?></dd>
						<dt><code>allowedEnv</code></dt><dd><?php esc_html_e( 'Names of environment variables servers may receive.', 'cyberdat' ); ?></dd>
						<dt><code>forbidLiteralSecrets</code></dt><dd><?php esc_html_e( 'true: flag detected literal credentials. Detection is heuristic and can miss unknown secret formats.', 'cyberdat' ); ?></dd>
						<dt><code>deniedTools</code></dt><dd><?php esc_html_e( 'Tool names that must not be offered (needs a tool list in the input).', 'cyberdat' ); ?></dd>
						<dt><code>allowAutoApprove</code></dt><dd><?php esc_html_e( 'false: no automatic approval (autoApprove, alwaysAllow, trust).', 'cyberdat' ); ?></dd>
						<dt><code>maxServers</code>, <code>maxToolsPerServer</code></dt><dd><?php esc_html_e( 'Upper limits, whole numbers.', 'cyberdat' ); ?></dd>
					</dl>
				</details>
			</div>
		</section>

		<div class="cd-la-actions">
			<button type="button" class="cd-la-button cd-la-button--primary" data-mcp-run><?php esc_html_e( 'Check configuration', 'cyberdat' ); ?></button>
			<button type="button" class="cd-la-button cd-la-button--ghost" data-mcp-cancel hidden><?php esc_html_e( 'Cancel', 'cyberdat' ); ?></button>
			<progress class="cd-la-progress" max="100" value="0" aria-label="<?php esc_attr_e( 'Check progress', 'cyberdat' ); ?>" data-mcp-progress hidden></progress>
		</div>
		<p class="cd-la-status" role="status" aria-live="polite" data-mcp-status></p>
		<div class="cd-la-callout cd-la-callout--error cd-mcp-error" role="alert" data-mcp-error hidden></div>

		<section class="cd-la-panel cd-la-results" aria-labelledby="cd-mcp-step-results" data-mcp-results hidden>
			<h2 id="cd-mcp-step-results" class="cd-la-step" tabindex="-1"><span aria-hidden="true">2</span> <?php esc_html_e( 'Review the results', 'cyberdat' ); ?></h2>
			<p class="cd-mcp-verdict" data-mcp-verdict></p>
			<p class="cd-la-summary" data-mcp-summary></p>
			<ul class="cd-mcp-warnings" data-mcp-warnings hidden></ul>
			<ul class="cd-mcp-notes" data-mcp-notes hidden></ul>
			<div class="cd-la-table-wrap" data-mcp-groups-wrap hidden>
				<table class="cd-la-table">
					<caption><?php esc_html_e( 'Findings by rule group', 'cyberdat' ); ?></caption>
					<thead><tr><th scope="col"><?php esc_html_e( 'Rule group', 'cyberdat' ); ?></th><th scope="col"><?php esc_html_e( 'Findings', 'cyberdat' ); ?></th></tr></thead>
					<tbody data-mcp-groups></tbody>
				</table>
			</div>
			<h3 class="cd-la-subheading" id="cd-mcp-list-title"><?php esc_html_e( 'Servers and tool lists', 'cyberdat' ); ?></h3>
			<p class="cd-la-help"><?php esc_html_e( 'Sorted by the highest severity. Recognized credentials are masked. Unknown secrets can be missed and may remain in names or excerpts. Use redacted configurations and review results before sharing.', 'cyberdat' ); ?></p>
			<ol class="cd-mcp-servers" aria-labelledby="cd-mcp-list-title" data-mcp-list></ol>
			<p class="cd-la-help" data-mcp-more hidden></p>
			<div class="cd-la-row">
				<button type="button" class="cd-la-button cd-la-button--secondary" data-mcp-report><?php esc_html_e( 'Download results (JSON)', 'cyberdat' ); ?></button>
			</div>
			<p class="cd-la-help"><?php esc_html_e( 'The report contains findings and one-line server summaries with best-effort masking of recognized credentials. Unrecognized secrets may remain. It does not contain the full configuration. It is created in your browser and saved only where you choose.', 'cyberdat' ); ?></p>
		</section>
	</div>

	<div class="cd-la-info">
		<section aria-labelledby="cd-mcp-how">
			<h2 id="cd-mcp-how"><?php esc_html_e( 'How it works', 'cyberdat' ); ?></h2>
			<ol>
				<li><?php esc_html_e( 'The text is parsed in a background worker by a JSON reader written for this tool. It records line numbers and duplicate keys and never evaluates anything.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Servers are recognized in the common client formats; tool lists are matched to their server when they are part of the same configuration.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Security check: CyberDat rules in eight groups look at secrets, launch commands, file access, remote addresses, tool capabilities, tool description poisoning, duplicate or look-alike names and general hygiene. High severity is reserved for very explicit risks or a combination of signals.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Policy check: your JSON policy is validated first, with clear messages for unknown settings and wrong types, then every server is compared with it.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Each finding shows the server, the location in the configuration with its line, the severity, an explanation and a suggested fix. No corrected configuration is generated: you decide what to change.', 'cyberdat' ); ?></li>
			</ol>
			<p class="cd-la-meta"><?php printf( esc_html__( 'Engine %1$s · rules %2$s', 'cyberdat' ), esc_html( $cyberdat_mcp['engine_version'] ), esc_html( $cyberdat_mcp['ruleset'] ) ); ?></p>
		</section>
		<section aria-labelledby="cd-mcp-privacy">
			<h2 id="cd-mcp-privacy"><?php esc_html_e( 'Privacy', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'This tool does not transmit the text you enter. The page’s Content Security Policy blocks scripts on this page from opening network connections, and URLs found in your configuration are never opened or checked online.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'If you select Cancel (or processing times out), the background worker is restarted and the browser downloads its static script files again from this site. Those requests contain no part of your input.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'This tool does not persist data: the configuration, your policy and the results are not written to cookies, local storage or the address bar, and the tool resets them when you close or reload the tab. Browser session restore, extensions, the clipboard and downloaded files are outside these controls; this is not secure erasure. The policy leaves the tab only if you download it.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Masking is best effort, not a guarantee of secret removal. The JSON report omits the full configuration but may retain unrecognized secrets in names or excerpts. Review every export before sharing.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Browser extensions you have installed can read page content. Use a private window without extensions for configurations that contain real credentials — or remove the credentials first.', 'cyberdat' ); ?></li>
			</ul>
		</section>
		<section aria-labelledby="cd-mcp-limits">
			<h2 id="cd-mcp-limits"><?php esc_html_e( 'Limitations', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'TOML and YAML are not supported. Only JSON (with comments) is read, so configurations in TOML or YAML must be converted first. Client settings stored elsewhere and environment variables resolved at runtime are not visible to the tool.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Conclusions are based only on the text of the configuration and tool lists. The tool does not start servers or run commands, does not check the reputation of packages, images or domains online, and does not audit server code. A server can behave differently from its description.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Tool descriptions and annotations come from the server and may be untrusted. A tool list you paste shows what the server reported at that moment; servers can change their tools later.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Look-alike package detection compares names with a short built-in list of well-known MCP packages. It does not contact npm, PyPI, container registries or MCP registries.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Description poisoning is recognized by wording, markup and hidden characters. Reworded or novel injections can be missed, and legitimate descriptions can occasionally match.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'The description-poisoning wording rules are English only. Instructions written in German, Russian or other languages are not recognized by wording; hidden characters and markup are still detected in any language.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Secret detection relies on variable names and known credential formats. Unusual secrets can be missed, and an ordinary value in a variable called “password” is reported as a secret.', 'cyberdat' ); ?></li>
			</ul>
		</section>
		<section aria-labelledby="cd-mcp-sources">
			<h2 id="cd-mcp-sources"><?php esc_html_e( 'Sources', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'All rules, explanations and the example policy are written by CyberDat. No external rule set or database is bundled.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Background reading: the Model Context Protocol specification by the MCP project (sections “Security and Trust & Safety” and “Tools”, which state that tool descriptions and annotations should be treated as untrusted). It is referenced here by name only; no text is copied.', 'cyberdat' ); ?></li>
			</ul>
		</section>
	</div>
</div>
