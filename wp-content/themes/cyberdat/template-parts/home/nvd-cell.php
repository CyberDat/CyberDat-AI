<?php
/** Escaped cached NVD details for one KEV table row. */
defined('ABSPATH') || exit;
$id=$args['id']??'';if(!cyberdat_nvd_id($id)){return;}
$cache=cyberdat_nvd_view($id);$assessment=$cache?$cache['record']['assessment']:null;
if(!$cache): ?><span class="table-status"><?php esc_html_e('NVD not loaded','cyberdat'); ?></span><?php else: ?>
<strong><?php echo esc_html($assessment?number_format($assessment['score'],1,'.',''):__('Not rated','cyberdat')); ?></strong> <span class="table-status"><?php echo esc_html($assessment?$assessment['severity']:__('Not rated','cyberdat')); ?></span><br>
<?php if($assessment): ?><small><?php echo esc_html('CVSS '.$assessment['version'].' · '.$assessment['source']); ?></small><br><?php endif; ?>
<small><?php echo esc_html(($cache['snapshot']?'SNAPSHOT · NOT LIVE · ':'').$cache['status']); ?> · <?php esc_html_e('Checked','cyberdat'); ?> <time datetime="<?php echo esc_attr(gmdate(DATE_W3C,$cache['checked_at'])); ?>"><?php echo esc_html(gmdate('Y-m-d H:i',$cache['checked_at']).' UTC'); ?></time></small>
<details><summary><?php esc_html_e('NVD description','cyberdat'); ?></summary><p class="chart-caption"><?php echo esc_html($cache['record']['description']?:__('No English description provided.','cyberdat')); ?></p></details>
<?php endif; ?><br><a href="<?php echo esc_url('https://nvd.nist.gov/vuln/detail/'.$id); ?>" aria-label="<?php echo esc_attr(sprintf(/* translators: %s: CVE ID. */__('Official NVD record for %s','cyberdat'),$id)); ?>">NVD ↗</a>
