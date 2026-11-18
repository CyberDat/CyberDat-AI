<?php
/**
 * Docker & Kubernetes Hardening Audit Generator — interactive workspace markup.
 * Static, server-rendered UI only. Files are checked in the browser by assets/js/container-hardening-audit/*.js;
 * they are never built, deployed, changed or posted to WordPress.
 * Inputs, file names and findings carry translate="no" and the notranslate class.
 */
defined( 'ABSPATH' ) || exit;
$cyberdat_cha = cyberdat_cha_config();
$cyberdat_cha_ta = 'class="cd-la-input notranslate" translate="no" spellcheck="false" autocomplete="off" autocapitalize="off" autocorrect="off" data-gramm="false" data-gramm_editor="false" data-enable-grammarly="false" data-lt-active="false"';
?>
<div class="cd-la cd-cha" data-cha data-worker-state="loading" data-worker-src="<?php echo esc_url( $cyberdat_cha['worker'] ); ?>">
	<noscript><p class="cd-la-callout cd-la-callout--warning"><?php esc_html_e( 'This tool needs JavaScript. Everything happens only in your browser, so nothing can run without it — and nothing is uploaded.', 'cyberdat' ); ?></p></noscript>
	<p class="cd-la-callout cd-la-callout--error" data-cha-unsupported hidden><?php esc_html_e( 'Your browser does not support the background processing this tool needs (Web Workers). Try a current version of Edge, Chrome, Firefox or Safari.', 'cyberdat' ); ?></p>

	<div class="cd-la-app" data-cha-app hidden>
		<p class="cd-la-callout cd-la-callout--privacy"><strong><?php esc_html_e( 'Local only.', 'cyberdat' ); ?></strong> <?php esc_html_e( 'Your text is analyzed in this browser tab. This tool does not transmit the text you enter — not to CyberDat, not to analytics, not to any registry or cluster — and this tool does not write it to persistent browser storage.', 'cyberdat' ); ?></p>
		<p class="cd-la-callout cd-la-callout--warning" role="note"><strong><?php esc_html_e( 'Static checks only.', 'cyberdat' ); ?></strong> <?php esc_html_e( 'Files are read as text. Nothing is built, pulled, deployed or changed, and no fixed file is generated: you get a checklist to review.', 'cyberdat' ); ?></p>
		<p class="cd-cha-state" role="status" aria-live="polite" data-cha-worker-status><?php esc_html_e( 'Starting the local checker…', 'cyberdat' ); ?></p>

		<section class="cd-la-panel" aria-labelledby="cd-cha-step-input">
			<h2 id="cd-cha-step-input" class="cd-la-step"><span aria-hidden="true">1</span> <?php esc_html_e( 'Add configuration files', 'cyberdat' ); ?></h2>
			<label class="cd-la-label" for="cd-cha-input"><?php esc_html_e( 'Dockerfile, Docker Compose file or Kubernetes YAML', 'cyberdat' ); ?></label>
			<textarea id="cd-cha-input" <?php echo $cyberdat_cha_ta; // phpcs:ignore WordPress.Security.EscapeOutput -- static attribute string ?> rows="16" aria-describedby="cd-cha-input-help cd-cha-size" data-cha-input></textarea>
			<p id="cd-cha-input-help" class="cd-la-help"><?php esc_html_e( 'Paste one file; Kubernetes YAML may hold several documents separated by ---. Up to 1 MB per file. Configuration files often contain host names and secrets; they stay in this tab.', 'cyberdat' ); ?></p>
			<p id="cd-cha-size" class="cd-la-source" aria-live="polite" data-cha-size></p>
			<label class="cd-la-label" for="cd-cha-kind"><?php esc_html_e( 'Type of the pasted text', 'cyberdat' ); ?></label>
			<select id="cd-cha-kind" class="cd-la-text cd-cha-select" data-cha-kind>
				<option value="auto"><?php esc_html_e( 'Detect automatically', 'cyberdat' ); ?></option>
				<option value="dockerfile"><?php esc_html_e( 'Dockerfile', 'cyberdat' ); ?></option>
				<option value="compose"><?php esc_html_e( 'Docker Compose', 'cyberdat' ); ?></option>
				<option value="kubernetes"><?php esc_html_e( 'Kubernetes YAML', 'cyberdat' ); ?></option>
			</select>
			<label class="cd-la-label" for="cd-cha-files"><?php esc_html_e( 'Or open files from this device', 'cyberdat' ); ?></label>
			<input id="cd-cha-files" class="cd-cha-file notranslate" translate="no" type="file" multiple accept=".yaml,.yml,.json,.txt,.dockerfile,.containerfile,text/plain,application/yaml" aria-describedby="cd-cha-files-help" data-cha-files>
			<p id="cd-cha-files-help" class="cd-la-help"><?php esc_html_e( 'Up to 20 files, read in this tab; their type is detected from the name (Dockerfile, Containerfile) or the content. Opened files are checked together with any pasted text.', 'cyberdat' ); ?></p>
			<ul class="cd-cha-filelist notranslate" translate="no" aria-label="<?php esc_attr_e( 'Opened files', 'cyberdat' ); ?>" data-cha-filelist hidden></ul>
			<div class="cd-la-row">
				<button type="button" class="cd-la-button cd-la-button--secondary" data-cha-sample="dockerfile"><?php esc_html_e( 'Load Dockerfile example', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--secondary" data-cha-sample="compose"><?php esc_html_e( 'Load Compose example', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--secondary" data-cha-sample="kubernetes"><?php esc_html_e( 'Load Kubernetes example', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--ghost" data-cha-clear><?php esc_html_e( 'Clear', 'cyberdat' ); ?></button>
			</div>
		</section>

		<div class="cd-la-actions">
			<button type="button" class="cd-la-button cd-la-button--primary" data-cha-run><?php esc_html_e( 'Generate checklist', 'cyberdat' ); ?></button>
			<button type="button" class="cd-la-button cd-la-button--ghost" data-cha-cancel hidden><?php esc_html_e( 'Cancel', 'cyberdat' ); ?></button>
			<progress class="cd-la-progress" max="100" value="0" aria-label="<?php esc_attr_e( 'Progress', 'cyberdat' ); ?>" data-cha-progress hidden></progress>
		</div>
		<p class="cd-la-status" role="status" aria-live="polite" data-cha-status></p>
		<div class="cd-la-callout cd-la-callout--error notranslate" translate="no" role="alert" data-cha-error hidden></div>

		<section class="cd-la-panel cd-la-results notranslate" translate="no" aria-labelledby="cd-cha-step-results" data-cha-results hidden>
			<h2 id="cd-cha-step-results" class="cd-la-step" tabindex="-1"><span aria-hidden="true">2</span> <b class="cd-cha-step-title"><?php esc_html_e( 'Review the checklist', 'cyberdat' ); ?></b></h2>
			<p class="cd-cha-verdict" data-cha-verdict></p>
			<p class="cd-la-summary" data-cha-summary></p>
			<div data-cha-files-out></div>
			<div class="cd-la-row">
				<button type="button" class="cd-la-button cd-la-button--secondary" data-cha-report="markdown"><?php esc_html_e( 'Download checklist (Markdown)', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--secondary" data-cha-report="json"><?php esc_html_e( 'Download checklist (JSON)', 'cyberdat' ); ?></button>
			</div>
			<p class="cd-la-help"><?php esc_html_e( 'The checklist contains the findings with file, document, container, line, explanation and suggested change; values that look like secrets are masked. It does not contain your files and no corrected file is generated.', 'cyberdat' ); ?></p>
		</section>
	</div>

	<div class="cd-la-info">
		<section aria-labelledby="cd-cha-how">
			<h2 id="cd-cha-how"><?php esc_html_e( 'How it works', 'cyberdat' ); ?></h2>
			<ol>
				<li><?php esc_html_e( 'Dockerfiles are split into instructions by a reader written for this tool (line continuations and heredocs included). Compose files and Kubernetes manifests are read by a YAML reader with limits on size, depth and time; anchors, aliases and tags are refused, and Helm templates are refused with a message because they must be rendered first.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'CyberDat rules then look for: root users and missing non-root settings; privileged mode, added capabilities, privilege escalation and writable root filesystems; host network, PID and IPC namespaces, hostPath and runtime sockets; latest or missing image tags; secrets in ENV, ARG, environment, env and manifests; missing resource limits and probes; ADD with a URL, curl or wget piped into a shell, and administration ports; default service accounts, token automount, wildcard RBAC rules, cluster-admin bindings and missing seccomp or AppArmor profiles.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Each finding names the file, document, object, container and line, explains why it matters and suggests a change. Hygiene items are grouped separately at info level. The result is a Markdown or JSON checklist; your files are not changed.', 'cyberdat' ); ?></li>
			</ol>
			<p class="cd-la-meta"><?php printf( esc_html__( 'Engine %1$s · rules %2$s', 'cyberdat' ), esc_html( $cyberdat_cha['engine_version'] ), esc_html( $cyberdat_cha['ruleset'] ) ); ?></p>
		</section>
		<section aria-labelledby="cd-cha-privacy">
			<h2 id="cd-cha-privacy"><?php esc_html_e( 'Privacy', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'This tool does not transmit the text you enter. The page has no server endpoint for your data, and its Content Security Policy blocks scripts on this page from opening network connections. Files you open are read in this tab and not uploaded.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Input fields, file names and findings are marked so that the browser’s built-in page translator does not translate them, because translating would send their text to a translation service.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'If you select Cancel (or processing times out), the background worker is restarted and the browser downloads its static script files again from this site. Those requests contain no part of your input.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'This tool does not persist data: input, findings and settings are not written to cookies, local storage or the address bar, and the tool resets them when you close or reload the tab. Browser session restore, extensions, the clipboard and downloaded files are outside these controls; this is not secure erasure.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Values that look like secrets are shown masked in findings and checklists, including long random-looking values that are not recognised; masking is best effort.', 'cyberdat' ); ?></li>
			</ul>
		</section>
		<section aria-labelledby="cd-cha-limits">
			<h2 id="cd-cha-limits"><?php esc_html_e( 'Limitations', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'A checklist is a starting point, not an audit. No findings does not mean a configuration is safe: images, base image contents, runtime defaults, admission policies, network policies and the cluster or host itself are not checked.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'The rules are written by CyberDat. They are not a CIS Benchmark and do not map to its recommendations; passing them says nothing about conformance with any standard.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Helm charts, Kustomize overlays and other templates must be rendered first. The YAML reader supports block and simple flow YAML; anchors, aliases, tags, merge keys and multi-line JSON are refused.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Settings inherited from elsewhere (base image USER and HEALTHCHECK, Compose override files, namespace defaults, Pod Security admission) are not known to the checks, so some findings may already be handled there.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Secret detection uses names and known formats and can miss secrets or flag harmless values.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Up to 20 files, 1 MB each and 4 MB in total. Processing stops after 30 seconds.', 'cyberdat' ); ?></li>
			</ul>
		</section>
		<section aria-labelledby="cd-cha-sources">
			<h2 id="cd-cha-sources"><?php esc_html_e( 'Sources', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'All rules, explanations, suggested changes and examples are written by CyberDat. No CIS Benchmark text, numbering or structure is used.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Background reading: the Kubernetes documentation by The Kubernetes Authors (CC BY 4.0), including the Pod Security Standards, and the Docker documentation by Docker, Inc. (Apache License 2.0). They are referenced here by name only; no text is copied.', 'cyberdat' ); ?></li>
			</ul>
		</section>
	</div>
</div>
