<?php
/**
 * AI Model Bill of Materials — interactive workspace markup.
 * Static, server-rendered UI only. Entries and pasted BOMs are processed in the browser by
 * assets/js/ai-model-bom/*.js; nothing is posted to WordPress and no model registry is contacted.
 * Every input, preview and result element carries translate="no" and the notranslate class so that a
 * built-in page translator does not send the entered text to a translation service.
 * Shared .cd-la-* component classes come from assets/css/tools-common.css.
 */
defined( 'ABSPATH' ) || exit;
$cyberdat_bom = cyberdat_bom_config();

if ( ! function_exists( 'cyberdat_bom_control' ) ) :
/** One labelled form control. $kind: text | textarea | select. */
function cyberdat_bom_control( $id, $label, $field, $kind = 'text', $help = '', $options = array(), $max = 1000 ) {
	$attrs = 'id="' . esc_attr( $id ) . '" class="cd-la-text notranslate" translate="no" spellcheck="false" autocomplete="off" data-gramm="false" data-gramm_editor="false" data-enable-grammarly="false" data-lt-active="false"';
	$attrs .= $field ? ' data-bom-field="' . esc_attr( $field ) . '"' : '';
	$attrs .= $help ? ' aria-describedby="' . esc_attr( $id ) . '-help"' : '';
	echo '<div class="cd-bom-control"><label class="cd-la-label" for="' . esc_attr( $id ) . '">' . esc_html( $label ) . '</label>';
	if ( 'textarea' === $kind ) {
		echo '<textarea ' . $attrs . ' rows="3" maxlength="' . (int) $max . '"></textarea>'; // phpcs:ignore WordPress.Security.EscapeOutput -- attributes escaped above
	} elseif ( 'select' === $kind ) {
		echo '<select ' . $attrs . '>'; // phpcs:ignore WordPress.Security.EscapeOutput -- attributes escaped above
		foreach ( $options as $value => $text ) {
			echo '<option value="' . esc_attr( $value ) . '">' . esc_html( $text ) . '</option>';
		}
		echo '</select>';
	} else {
		echo '<input type="text" ' . $attrs . ' maxlength="' . (int) $max . '">'; // phpcs:ignore WordPress.Security.EscapeOutput -- attributes escaped above
	}
	if ( $help ) {
		echo '<p id="' . esc_attr( $id ) . '-help" class="cd-la-help">' . esc_html( $help ) . '</p>';
	}
	echo '</div>';
}

/** Column control inside a repeatable row template (ids and label links are set by app.js). */
function cyberdat_bom_col( $col, $label, $kind = 'text', $options = array(), $max = 1000 ) {
	$attrs = 'class="cd-la-text notranslate" translate="no" spellcheck="false" autocomplete="off" data-gramm="false" data-gramm_editor="false" data-enable-grammarly="false" data-lt-active="false" data-bom-col="' . esc_attr( $col ) . '"';
	echo '<div class="cd-bom-control"><label class="cd-la-label">' . esc_html( $label ) . '</label>';
	if ( 'select' === $kind ) {
		echo '<select ' . $attrs . '>'; // phpcs:ignore WordPress.Security.EscapeOutput -- attributes escaped above
		foreach ( $options as $value => $text ) {
			echo '<option value="' . esc_attr( $value ) . '">' . esc_html( $text ) . '</option>';
		}
		echo '</select>';
	} else {
		echo '<input type="text" ' . $attrs . ' maxlength="' . (int) $max . '">'; // phpcs:ignore WordPress.Security.EscapeOutput -- attributes escaped above
	}
	echo '</div>';
}
endif;

$cyberdat_bom_groups = array(
	'weights'      => array( __( 'Weights files', 'cyberdat' ), __( 'Add weights file', 'cyberdat' ), __( 'Weights file', 'cyberdat' ) ),
	'datasets'     => array( __( 'Data', 'cyberdat' ), __( 'Add dataset', 'cyberdat' ), __( 'Dataset', 'cyberdat' ) ),
	'dependencies' => array( __( 'Dependencies', 'cyberdat' ), __( 'Add dependency', 'cyberdat' ), __( 'Dependency', 'cyberdat' ) ),
	'apis'         => array( __( 'External APIs', 'cyberdat' ), __( 'Add external API', 'cyberdat' ), __( 'External API', 'cyberdat' ) ),
	'metrics'      => array( __( 'Quality metrics', 'cyberdat' ), __( 'Add metric', 'cyberdat' ), __( 'Metric', 'cyberdat' ) ),
);
?>
<div class="cd-la cd-bom" data-bom data-worker-src="<?php echo esc_url( $cyberdat_bom['worker'] ); ?>">
	<noscript><p class="cd-la-callout cd-la-callout--warning"><?php esc_html_e( 'This tool needs JavaScript. Everything happens only in your browser, so nothing can run without it — and nothing is uploaded.', 'cyberdat' ); ?></p></noscript>
	<p class="cd-la-callout cd-la-callout--error" data-bom-unsupported hidden><?php esc_html_e( 'Your browser does not support the background processing this tool needs (Web Workers). Try a current version of Edge, Chrome, Firefox or Safari.', 'cyberdat' ); ?></p>

	<div class="cd-la-app" data-bom-app hidden>
		<p class="cd-la-callout cd-la-callout--privacy"><strong><?php esc_html_e( 'Local only.', 'cyberdat' ); ?></strong> <?php esc_html_e( 'Your entries are processed in this browser tab. This tool does not transmit the text you enter — not to CyberDat, not to analytics, not to any model registry — and this tool does not write it to persistent browser storage.', 'cyberdat' ); ?></p>
		<p class="cd-la-callout cd-la-callout--warning" role="note"><strong><?php esc_html_e( 'A documentation aid, not an assessment.', 'cyberdat' ); ?></strong> <?php esc_html_e( 'The document reflects only what you enter. The tool does not check whether entries are true, does not contact model registries and does not evaluate the model itself.', 'cyberdat' ); ?></p>

		<fieldset class="cd-bom-modes">
			<legend class="cd-la-label"><?php esc_html_e( 'What do you want to do?', 'cyberdat' ); ?></legend>
			<label class="cd-bom-mode"><input type="radio" name="cd-bom-mode" value="build" checked data-bom-mode> <span><strong><?php esc_html_e( 'Build', 'cyberdat' ); ?></strong> — <?php esc_html_e( 'fill in the form and get an AI BOM (CycloneDX JSON and Markdown)', 'cyberdat' ); ?></span></label>
			<label class="cd-bom-mode"><input type="radio" name="cd-bom-mode" value="review" data-bom-mode> <span><strong><?php esc_html_e( 'Review', 'cyberdat' ); ?></strong> — <?php esc_html_e( 'paste an existing AI BOM in CycloneDX JSON and get a list of gaps and risks', 'cyberdat' ); ?></span></label>
		</fieldset>

		<section class="cd-la-panel" aria-labelledby="cd-bom-step-build" data-bom-build-panel>
			<h2 id="cd-bom-step-build" class="cd-la-step"><span aria-hidden="true">1</span> <?php esc_html_e( 'Describe the AI system', 'cyberdat' ); ?></h2>
			<p class="cd-la-help"><?php esc_html_e( 'All fields are optional; empty fields are reported as gaps. Do not enter passwords, keys or tokens: refer to a secret by its name in your vault instead.', 'cyberdat' ); ?></p>
			<div class="cd-la-row">
				<button type="button" class="cd-la-button cd-la-button--secondary" data-bom-sample><?php esc_html_e( 'Load example', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--ghost" data-bom-clear><?php esc_html_e( 'Clear everything', 'cyberdat' ); ?></button>
			</div>

			<fieldset class="cd-bom-group">
				<legend><?php esc_html_e( 'Model', 'cyberdat' ); ?></legend>
				<div class="cd-bom-grid">
					<?php
					cyberdat_bom_control( 'cd-bom-model-name', __( 'Name', 'cyberdat' ), 'model.name' );
					cyberdat_bom_control( 'cd-bom-model-version', __( 'Version', 'cyberdat' ), 'model.version', 'text', __( 'Exact version, snapshot date or revision — not “latest” or a branch.', 'cyberdat' ) );
					cyberdat_bom_control( 'cd-bom-model-vendor', __( 'Vendor', 'cyberdat' ), 'model.vendor' );
					cyberdat_bom_control( 'cd-bom-model-license', __( 'License', 'cyberdat' ), 'model.license', 'text', __( 'SPDX identifier such as Apache-2.0, or the name of the terms.', 'cyberdat' ) );
					cyberdat_bom_control( 'cd-bom-model-type', __( 'Type', 'cyberdat' ), 'model.type', 'select', '', array( '' => __( '— not stated —', 'cyberdat' ), 'own' => __( 'Own model', 'cyberdat' ), 'fine-tuned' => __( 'Fine-tuned model', 'cyberdat' ), 'external-api' => __( 'External model used through an API', 'cyberdat' ) ) );
					cyberdat_bom_control( 'cd-bom-model-base', __( 'Base model (for a fine-tuned model)', 'cyberdat' ), 'model.baseModel.name' );
					cyberdat_bom_control( 'cd-bom-model-base-version', __( 'Base model version', 'cyberdat' ), 'model.baseModel.version' );
					?>
				</div>
			</fieldset>

			<?php foreach ( $cyberdat_bom_groups as $cyberdat_key => $cyberdat_g ) : ?>
				<?php if ( 'apis' === $cyberdat_key ) : ?>
					<fieldset class="cd-bom-group">
						<legend><?php esc_html_e( 'Deployment', 'cyberdat' ); ?></legend>
						<?php cyberdat_bom_control( 'cd-bom-deployment', __( 'Where it runs', 'cyberdat' ), 'deployment.environment', 'textarea', __( 'For example: on-premises cluster, cloud region, user devices.', 'cyberdat' ), array(), 4000 ); ?>
				<?php elseif ( 'metrics' === $cyberdat_key ) : ?>
					<fieldset class="cd-bom-group">
						<legend><?php esc_html_e( 'Purpose and limitations', 'cyberdat' ); ?></legend>
						<?php
						cyberdat_bom_control( 'cd-bom-purpose', __( 'Intended purpose', 'cyberdat' ), 'purpose', 'textarea', __( 'What the model is used for and by whom.', 'cyberdat' ), array(), 20000 );
						cyberdat_bom_control( 'cd-bom-limitations', __( 'Limitations', 'cyberdat' ), 'limitations', 'textarea', __( 'Languages, inputs and situations where results are unreliable or the model must not be used.', 'cyberdat' ), array(), 20000 );
						?>
					</fieldset>
					<fieldset class="cd-bom-group">
						<legend><?php esc_html_e( 'Quality and safety evaluation', 'cyberdat' ); ?></legend>
				<?php else : ?>
					<fieldset class="cd-bom-group">
				<?php endif; ?>
				<?php if ( 'apis' === $cyberdat_key || 'metrics' === $cyberdat_key ) : ?>
					<h3 class="cd-bom-subhead" id="cd-bom-<?php echo esc_attr( $cyberdat_key ); ?>-title"><?php echo esc_html( $cyberdat_g[0] ); ?></h3>
				<?php else : ?>
					<legend id="cd-bom-<?php echo esc_attr( $cyberdat_key ); ?>-title"><?php echo esc_html( $cyberdat_g[0] ); ?></legend>
				<?php endif; ?>
					<ol class="cd-bom-rows" data-bom-rows="<?php echo esc_attr( $cyberdat_key ); ?>" data-bom-row-label="<?php echo esc_attr( $cyberdat_g[2] ); ?>" aria-labelledby="cd-bom-<?php echo esc_attr( $cyberdat_key ); ?>-title"></ol>
					<template data-bom-template="<?php echo esc_attr( $cyberdat_key ); ?>">
						<li class="cd-bom-row">
							<p class="cd-bom-row__title" data-bom-row-title></p>
							<div class="cd-bom-grid">
								<?php
								if ( 'weights' === $cyberdat_key ) {
									cyberdat_bom_col( 'file', __( 'File name', 'cyberdat' ) );
									cyberdat_bom_col( 'format', __( 'Format', 'cyberdat' ) );
									cyberdat_bom_col( 'hashAlg', __( 'Hash algorithm', 'cyberdat' ), 'select', array( 'SHA-256' => 'SHA-256', 'SHA-384' => 'SHA-384', 'SHA-512' => 'SHA-512', 'SHA3-256' => 'SHA3-256', 'SHA-1' => 'SHA-1', 'MD5' => 'MD5' ) );
									cyberdat_bom_col( 'hash', __( 'Hash (hex digest)', 'cyberdat' ), 'text', array(), 200 );
									cyberdat_bom_col( 'source', __( 'Source', 'cyberdat' ), 'text', array(), 2000 );
								} elseif ( 'datasets' === $cyberdat_key ) {
									cyberdat_bom_col( 'name', __( 'Name', 'cyberdat' ) );
									cyberdat_bom_col( 'role', __( 'Used for', 'cyberdat' ), 'select', array( '' => __( '— not stated —', 'cyberdat' ), 'training' => __( 'Training', 'cyberdat' ), 'fine-tuning' => __( 'Fine-tuning', 'cyberdat' ), 'evaluation' => __( 'Evaluation', 'cyberdat' ) ) );
									cyberdat_bom_col( 'source', __( 'Source', 'cyberdat' ), 'text', array(), 2000 );
									cyberdat_bom_col( 'license', __( 'License', 'cyberdat' ) );
									cyberdat_bom_col( 'personalData', __( 'Contains personal data', 'cyberdat' ), 'select', array( '' => __( '— not stated —', 'cyberdat' ), 'yes' => __( 'Yes', 'cyberdat' ), 'no' => __( 'No', 'cyberdat' ), 'unknown' => __( 'Unknown', 'cyberdat' ) ) );
								} elseif ( 'dependencies' === $cyberdat_key ) {
									cyberdat_bom_col( 'kind', __( 'Kind', 'cyberdat' ), 'select', array( 'framework' => __( 'Framework', 'cyberdat' ), 'library' => __( 'Library', 'cyberdat' ) ) );
									cyberdat_bom_col( 'name', __( 'Name', 'cyberdat' ) );
									cyberdat_bom_col( 'version', __( 'Version', 'cyberdat' ) );
								} elseif ( 'apis' === $cyberdat_key ) {
									cyberdat_bom_col( 'name', __( 'Name', 'cyberdat' ) );
									cyberdat_bom_col( 'url', __( 'Address', 'cyberdat' ), 'text', array(), 2000 );
								} else {
									cyberdat_bom_col( 'type', __( 'Metric', 'cyberdat' ) );
									cyberdat_bom_col( 'value', __( 'Value', 'cyberdat' ) );
									cyberdat_bom_col( 'slice', __( 'Measured on', 'cyberdat' ) );
								}
								?>
							</div>
							<button type="button" class="cd-la-button cd-la-button--ghost cd-bom-remove" data-bom-remove><?php esc_html_e( 'Remove', 'cyberdat' ); ?></button>
						</li>
					</template>
					<button type="button" class="cd-la-button cd-la-button--secondary" data-bom-add="<?php echo esc_attr( $cyberdat_key ); ?>"><?php echo esc_html( $cyberdat_g[1] ); ?></button>
				<?php if ( 'metrics' === $cyberdat_key ) : ?>
					<?php cyberdat_bom_control( 'cd-bom-safety', __( 'Safety evaluation', 'cyberdat' ), 'evaluation.safety', 'textarea', __( 'How the model was checked for harmful or unsafe output, data leakage or misuse, and when.', 'cyberdat' ), array(), 20000 ); ?>
				<?php endif; ?>
				</fieldset>
			<?php endforeach; ?>

			<fieldset class="cd-bom-group">
				<legend><?php esc_html_e( 'Responsible', 'cyberdat' ); ?></legend>
				<div class="cd-bom-grid">
					<?php
					cyberdat_bom_control( 'cd-bom-owner-name', __( 'Person or team', 'cyberdat' ), 'owner.name' );
					cyberdat_bom_control( 'cd-bom-owner-org', __( 'Organization', 'cyberdat' ), 'owner.organization' );
					cyberdat_bom_control( 'cd-bom-owner-contact', __( 'Contact (e-mail or URL)', 'cyberdat' ), 'owner.contact' );
					?>
				</div>
			</fieldset>
		</section>

		<section class="cd-la-panel" aria-labelledby="cd-bom-step-review" data-bom-review-panel hidden>
			<h2 id="cd-bom-step-review" class="cd-la-step"><span aria-hidden="true">1</span> <?php esc_html_e( 'Add an AI BOM', 'cyberdat' ); ?></h2>
			<label class="cd-la-label" for="cd-bom-input"><?php esc_html_e( 'AI BOM in CycloneDX JSON', 'cyberdat' ); ?></label>
			<textarea id="cd-bom-input" class="cd-la-input notranslate" translate="no" rows="14" spellcheck="false" autocomplete="off" autocapitalize="off" autocorrect="off" data-gramm="false" data-gramm_editor="false" data-enable-grammarly="false" data-lt-active="false" aria-describedby="cd-bom-input-help cd-bom-source" data-bom-input></textarea>
			<p id="cd-bom-input-help" class="cd-la-help"><?php esc_html_e( 'CycloneDX JSON, specVersion 1.5 to 1.7, with components of type machine-learning-model, data, file, framework or library. Strict JSON: comments and trailing commas are reported as errors. Up to 5 MB.', 'cyberdat' ); ?></p>
			<div class="cd-la-row">
				<label class="cd-la-file">
					<span class="cd-la-button cd-la-button--secondary" aria-hidden="true"><?php esc_html_e( 'Load a JSON file', 'cyberdat' ); ?></span>
					<input class="cd-la-file__input notranslate" translate="no" id="cd-bom-file" type="file" accept=".json,.cdx.json,.txt,application/json,application/vnd.cyclonedx+json,text/plain" aria-label="<?php esc_attr_e( 'Load a JSON file', 'cyberdat' ); ?>" data-bom-file>
				</label>
				<button type="button" class="cd-la-button cd-la-button--secondary" data-bom-review-sample><?php esc_html_e( 'Load example BOM', 'cyberdat' ); ?></button>
				<button type="button" class="cd-la-button cd-la-button--ghost" data-bom-review-clear><?php esc_html_e( 'Clear', 'cyberdat' ); ?></button>
			</div>
			<p id="cd-bom-source" class="cd-la-source notranslate" translate="no" aria-live="polite" data-bom-source></p>
		</section>

		<div class="cd-la-actions">
			<button type="button" class="cd-la-button cd-la-button--primary" data-bom-run><?php esc_html_e( 'Check and build', 'cyberdat' ); ?></button>
			<button type="button" class="cd-la-button cd-la-button--ghost" data-bom-cancel hidden><?php esc_html_e( 'Cancel', 'cyberdat' ); ?></button>
			<progress class="cd-la-progress" max="100" value="0" aria-label="<?php esc_attr_e( 'Progress', 'cyberdat' ); ?>" data-bom-progress hidden></progress>
		</div>
		<p class="cd-la-status" role="status" aria-live="polite" data-bom-status></p>
		<div class="cd-la-callout cd-la-callout--error cd-bom-error notranslate" translate="no" role="alert" data-bom-error hidden></div>

		<section class="cd-la-panel cd-la-results notranslate" translate="no" aria-labelledby="cd-bom-step-results" data-bom-results hidden>
			<h2 id="cd-bom-step-results" class="cd-la-step" tabindex="-1"><span aria-hidden="true">2</span> <b class="cd-bom-step-title" data-bom-results-title><?php esc_html_e( 'Review the gaps', 'cyberdat' ); ?></b></h2>
			<p class="cd-bom-verdict" data-bom-verdict></p>
			<p class="cd-la-summary" data-bom-summary></p>
			<ul class="cd-bom-notes" data-bom-notes hidden></ul>
			<div class="cd-la-table-wrap" data-bom-groups-wrap hidden>
				<table class="cd-la-table">
					<caption><?php esc_html_e( 'Findings by group', 'cyberdat' ); ?></caption>
					<thead><tr><th scope="col"><?php esc_html_e( 'Group', 'cyberdat' ); ?></th><th scope="col"><?php esc_html_e( 'Findings', 'cyberdat' ); ?></th></tr></thead>
					<tbody data-bom-groups></tbody>
				</table>
			</div>
			<ol class="cd-bom-findings" aria-label="<?php esc_attr_e( 'Findings', 'cyberdat' ); ?>" data-bom-list></ol>
			<p class="cd-la-help" data-bom-more hidden></p>

			<div data-bom-structure-wrap hidden>
				<h3 class="cd-la-subheading"><?php esc_html_e( 'Structure', 'cyberdat' ); ?></h3>
				<p class="cd-la-help"><?php esc_html_e( 'Checked against the subset of CycloneDX fields that this tool reads and writes; other fields are not validated.', 'cyberdat' ); ?></p>
				<ul class="cd-bom-structure" data-bom-structure></ul>
			</div>

			<div data-bom-inventory-wrap hidden>
				<h3 class="cd-la-subheading"><?php esc_html_e( 'What the BOM contains', 'cyberdat' ); ?></h3>
				<dl class="cd-bom-inventory" data-bom-inventory></dl>
				<div class="cd-la-row">
					<button type="button" class="cd-la-button cd-la-button--secondary" data-bom-edit><?php esc_html_e( 'Open in the Build form', 'cyberdat' ); ?></button>
					<button type="button" class="cd-la-button cd-la-button--secondary" data-bom-report><?php esc_html_e( 'Download findings (JSON)', 'cyberdat' ); ?></button>
				</div>
				<p class="cd-la-help"><?php esc_html_e( 'The findings file contains the findings with recognized secrets masked, not the BOM itself.', 'cyberdat' ); ?></p>
			</div>

			<div data-bom-export-wrap hidden>
				<h3 class="cd-la-subheading"><?php esc_html_e( 'Export', 'cyberdat' ); ?></h3>
				<div class="cd-la-callout cd-la-callout--error" data-bom-secret-warning hidden>
					<p class="cd-bom-secret-text" data-bom-secret-text></p>
				</div>
				<div class="cd-la-row">
					<button type="button" class="cd-la-button cd-la-button--primary" data-bom-download-json><?php esc_html_e( 'Download CycloneDX JSON', 'cyberdat' ); ?></button>
					<button type="button" class="cd-la-button cd-la-button--secondary" data-bom-download-md><?php esc_html_e( 'Download Markdown', 'cyberdat' ); ?></button>
				</div>
				<p class="cd-la-help"><?php esc_html_e( 'Both files mask detected secrets and unrecognized long token-shaped values before formatting. They are created in your browser and saved only where you choose. Remove secrets from the original source data and review the exports before sharing.', 'cyberdat' ); ?></p>
				<details class="cd-bom-preview">
					<summary><?php esc_html_e( 'Preview: CycloneDX JSON', 'cyberdat' ); ?></summary>
					<pre class="cd-la-preview notranslate" translate="no" tabindex="0" data-bom-preview-json></pre>
				</details>
				<details class="cd-bom-preview">
					<summary><?php esc_html_e( 'Preview: Markdown', 'cyberdat' ); ?></summary>
					<pre class="cd-la-preview notranslate" translate="no" tabindex="0" data-bom-preview-md></pre>
				</details>
			</div>
		</section>
	</div>

	<div class="cd-la-info">
		<section aria-labelledby="cd-bom-how">
			<h2 id="cd-bom-how"><?php esc_html_e( 'How it works', 'cyberdat' ); ?></h2>
			<ol>
				<li><?php esc_html_e( 'Build: the form is read in this tab and checked by CyberDat rules in a background worker. The result is a CycloneDX 1.7 document with a component of type machine-learning-model and its model card, plus a Markdown version for people to read.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Review: the pasted JSON is read by a strict JSON reader written for this tool, which records line numbers and duplicate keys and never evaluates anything. Keys are matched regardless of case, underscores, hyphens and camelCase, and non-standard spellings are reported.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Rules in ten groups look for missing or unknown licenses, floating versions, weights without a hash or in pickle-based formats, fine-tuned models without a base model, datasets without a source or personal-data status, unpinned dependencies, http:// addresses, secrets, and missing purpose, limitations, evaluation or owner.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Each finding shows where it was found, its severity, why it matters and a suggested change. Secrets are shown only as their type and a masked fragment.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Fields that CycloneDX has no place for (model type, personal-data status, dataset use, deployment, safety evaluation) are stored as properties named cyberdat:aibom:…, so a document exported here can be reviewed here again with the same content.', 'cyberdat' ); ?></li>
			</ol>
			<?php require_once dirname( __DIR__, 2 ) . '/inc/tools-owasp-2026.php'; ?>
			<p class="cd-la-meta"><?php printf( esc_html__( 'Engine %1$s · rules %2$s · CycloneDX %3$s · rules updated %4$s', 'cyberdat' ), esc_html( $cyberdat_bom['engine_version'] ), esc_html( $cyberdat_bom['ruleset'] ), esc_html( $cyberdat_bom['spec_version'] ), esc_html( cyberdat_rules_updated( $cyberdat_bom['ruleset'] ) ) ); ?></p>
			<?php echo cyberdat_tools_owasp_line( 'ai-model-bom' ); // phpcs:ignore WordPress.Security.EscapeOutput -- escaped in the helper ?>
		</section>
		<section aria-labelledby="cd-bom-privacy">
			<h2 id="cd-bom-privacy"><?php esc_html_e( 'Privacy', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'This tool does not transmit the text you enter. The page has no server endpoint for your data, and its Content Security Policy blocks scripts on this page from opening network connections. Addresses in your entries are never opened or checked online.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Input fields, previews and results are marked so that the browser’s built-in page translator does not translate them, because translating would send their text to a translation service.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'If you select Cancel (or processing times out), the background worker is restarted and the browser downloads its static script files again from this site. Those requests contain no part of your input.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'This tool does not persist data: the form, the pasted BOM and the results are not written to cookies, local storage or the address bar, and the tool resets them when you close or reload the tab. Browser session restore, extensions, the clipboard and downloaded files are outside these controls; this is not secure erasure.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Masking is best effort and cannot recognize every possible secret. Findings, previews and exports mask detected values. Long token-shaped values may be masked conservatively even when they are identifiers. Validated weights digests in the dedicated hash field are preserved. Remove secrets from the original source data.', 'cyberdat' ); ?></li>
			</ul>
		</section>
		<section aria-labelledby="cd-bom-limits">
			<h2 id="cd-bom-limits"><?php esc_html_e( 'Limitations', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'The document reflects only what you entered. The tool does not check whether the entries are true, does not contact model registries, package indexes or dataset sources, and does not evaluate the model or its outputs.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'The tool helps document a model and its supply chain. It does not determine whether a system meets any law, regulation or standard.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Only CycloneDX JSON is supported. SPDX, CycloneDX XML and other formats are not read or written in this version.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'The structure check covers only the CycloneDX fields this tool uses. License identifiers are not checked against the full SPDX list, and other parts of a document are not validated.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( '“Unknown” is recognized in English, German and Russian and in common abbreviations such as n/a and TBD; other wordings are read as a stated value.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Pickle-based formats are recognized by file extension and the format you enter. A file can be pickle-based under another name.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Secret detection relies on known credential formats, secret-like names and a heuristic for long random-looking values. Unusual secrets can be missed, and an ordinary long value can be reported.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Text is stored in Unicode NFC: names typed with separate combining marks are exported in their composed form, which looks the same.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Review reads up to 5 MB. Processing stops after 120 seconds.', 'cyberdat' ); ?></li>
			</ul>
		</section>
		<section aria-labelledby="cd-bom-sources">
			<h2 id="cd-bom-sources"><?php esc_html_e( 'Sources', 'cyberdat' ); ?></h2>
			<ul>
				<li><?php esc_html_e( 'All rules, explanations and recommendations are written by CyberDat. No external rule set, model registry or database is bundled.', 'cyberdat' ); ?></li>
				<li><?php esc_html_e( 'Format: the CycloneDX specification, version 1.7, by the OWASP CycloneDX project, published under the Apache License 2.0. It is referenced here by name only; no specification or schema text is copied, and the structure check is CyberDat’s own.', 'cyberdat' ); ?></li>
			</ul>
		</section>
	</div>
</div>
