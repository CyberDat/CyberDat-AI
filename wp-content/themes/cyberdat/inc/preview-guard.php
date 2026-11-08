<?php
/** Explicit preview contexts; no request parameter can turn preview or live APIs on. */
defined('ABSPATH') || exit;
function cyberdat_playground_preview() {
 return defined('CYBERDAT_PLAYGROUND') && CYBERDAT_PLAYGROUND === true
  && in_array(wp_get_environment_type(), ['local','development'], true);
}
function cyberdat_staging_url($url) {
 $parts=wp_parse_url($url);
 return is_array($parts) && ($parts['scheme']??'')==='https'
  && strtolower($parts['host']??'')==='staging.cyberdat.eu'
  && (!isset($parts['port']) || $parts['port']===443)
  && in_array($parts['path']??'', ['', '/'], true)
  && !isset($parts['user']) && !isset($parts['pass']) && !isset($parts['query']) && !isset($parts['fragment']);
}
function cyberdat_home_preview_allowed() {
 if(wp_get_environment_type()==='production' || str_starts_with(str_replace('\\','/',ABSPATH),'/var/www/cyberdat/')){return false;}
 if(cyberdat_playground_preview()){return true;}
 if(defined('CYBERDAT_PLAYGROUND') && CYBERDAT_PLAYGROUND){return false;}
 return wp_get_environment_type()==='staging'
  && defined('CYBERDAT_STAGING_PREVIEW') && CYBERDAT_STAGING_PREVIEW === true
  && rtrim(str_replace('\\','/',ABSPATH),'/').'/'==='/var/www/cyberdat-staging/public/'
  && cyberdat_staging_url(home_url('/')) && cyberdat_staging_url(site_url('/'))
  && isset($_SERVER['REMOTE_USER']) && is_string($_SERVER['REMOTE_USER']) && $_SERVER['REMOTE_USER']!=='';
}
