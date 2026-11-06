<?php
/** Playground fixtures only. Never install on production. */
defined('ABSPATH') || exit;
if (!defined('CYBERDAT_PLAYGROUND') || !CYBERDAT_PLAYGROUND) { return; }

add_filter('pre_wp_mail', '__return_true');
add_filter('wp_robots', function ($robots) {
    unset($robots['index'], $robots['nofollow']);
    $robots['noindex'] = true;
    $robots['follow'] = true;
    return $robots;
});
add_action('send_headers', function () {
    header('X-Robots-Tag: noindex, follow', true);
});
add_action('init', function () {
    register_taxonomy('editorial_format', ['post'], [
        'label'=>'Editorial Formats', 'public'=>true, 'hierarchical'=>false,
        'show_ui'=>true, 'show_admin_column'=>true, 'show_in_rest'=>true,
        'rest_base'=>'editorial-formats', 'query_var'=>'editorial_format', 'rewrite'=>false,
    ]);
    add_rewrite_rule('^(news|analysis|guides|learning)/page/([0-9]+)/?$', 'index.php?editorial_format=$matches[1]&paged=$matches[2]', 'top');
    add_rewrite_rule('^(news|analysis|guides|learning)/?$', 'index.php?editorial_format=$matches[1]', 'top');
}, 5);
add_filter('term_link', function ($url, $term, $taxonomy) {
    return 'editorial_format' === $taxonomy ? home_url('/'.$term->slug.'/') : $url;
}, 10, 3);
