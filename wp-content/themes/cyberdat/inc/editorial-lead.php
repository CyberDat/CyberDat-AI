<?php
/** Dynamic editorial lead, with a standard WordPress editor control. */
defined( 'ABSPATH' ) || exit;

function cyberdat_featured_meta_key() { return '_cyberdat_featured_story'; }

function cyberdat_register_featured_meta() {
 register_post_meta( 'post', cyberdat_featured_meta_key(), [
  'type'=>'boolean', 'single'=>true, 'default'=>false, 'show_in_rest'=>false,
  'sanitize_callback'=>'rest_sanitize_boolean',
  'auth_callback'=>static function ( $allowed, $key, $post_id ) { return current_user_can( 'edit_post', $post_id ); },
 ] );
}
add_action( 'init', 'cyberdat_register_featured_meta' );

function cyberdat_featured_box( $post ) {
 wp_nonce_field( 'cyberdat_save_featured_story', 'cyberdat_featured_nonce' );
 ?>
 <label for="cyberdat-featured-story"><input type="checkbox" id="cyberdat-featured-story" name="cyberdat_featured_story" value="1" <?php checked( (bool) get_post_meta( $post->ID, cyberdat_featured_meta_key(), true ) ); ?>> <?php esc_html_e( 'Use as Featured Story', 'cyberdat' ); ?></label>
 <p class="description"><?php esc_html_e( 'Among marked, public published posts, the latest publication date wins; equal dates use the highest post ID. If none is marked, the latest public published post is used.', 'cyberdat' ); ?></p>
 <?php
}
function cyberdat_add_featured_box( $post ) {
 if ( current_user_can( 'edit_post', $post->ID ) ) {
  add_meta_box( 'cyberdat-featured-story', __( 'CyberDat — Featured Story', 'cyberdat' ), 'cyberdat_featured_box', 'post', 'side', 'default', ['__block_editor_compatible_meta_box'=>true] );
 }
}
add_action( 'add_meta_boxes_post', 'cyberdat_add_featured_box' );

function cyberdat_save_featured_story( $post_id ) {
 if ( ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) || wp_is_post_autosave( $post_id ) || wp_is_post_revision( $post_id ) || 'post' !== get_post_type( $post_id ) ) { return; }
 if ( ! isset( $_POST['cyberdat_featured_nonce'] ) || ! is_string( $_POST['cyberdat_featured_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['cyberdat_featured_nonce'] ) ), 'cyberdat_save_featured_story' ) || ! current_user_can( 'edit_post', $post_id ) ) { return; }
 if ( isset( $_POST['cyberdat_featured_story'] ) && ( ! is_string( $_POST['cyberdat_featured_story'] ) || '1' !== wp_unslash( $_POST['cyberdat_featured_story'] ) ) ) { return; }
 if ( isset( $_POST['cyberdat_featured_story'] ) ) {
  update_post_meta( $post_id, cyberdat_featured_meta_key(), true );
 } else {
  delete_post_meta( $post_id, cyberdat_featured_meta_key() );
 }
}
add_action( 'save_post_post', 'cyberdat_save_featured_story' );

function cyberdat_featured_story() {
 $base = ['post_type'=>'post','post_status'=>'publish','has_password'=>false,'posts_per_page'=>1,'orderby'=>['date'=>'DESC','ID'=>'DESC'],'ignore_sticky_posts'=>true,'no_found_rows'=>true,'cache_results'=>false];
 $query = new WP_Query( array_merge( $base, ['meta_query'=>[['key'=>cyberdat_featured_meta_key(),'value'=>'1','compare'=>'=']]] ) );
 if ( ! $query->posts ) { $query = new WP_Query( $base ); }
 return $query->posts[0] ?? null;
}
function cyberdat_briefing_posts( $featured_id = 0 ) {
 if ( ! taxonomy_exists( 'editorial_format' ) || ! term_exists( 'news', 'editorial_format' ) ) { return []; }
 $query = new WP_Query( [
  'post_type'=>'post','post_status'=>'publish','has_password'=>false,'posts_per_page'=>4,
  'orderby'=>['date'=>'DESC','ID'=>'DESC'],'ignore_sticky_posts'=>true,'no_found_rows'=>true,'cache_results'=>false,
  'post__not_in'=>$featured_id ? [(int)$featured_id] : [],
  'tax_query'=>[['taxonomy'=>'editorial_format','field'=>'slug','terms'=>['news']]],
 ] );
 return $query->posts;
}
function cyberdat_editorial_category( $post_id ) {
 $terms = get_the_category( $post_id );
 usort( $terms, static function ( $a, $b ) { return $a->term_id <=> $b->term_id; } );
 return $terms[0]->name ?? '';
}
function cyberdat_editorial_format( $post_id ) {
 $terms = get_the_terms( $post_id, 'editorial_format' );
 if ( ! $terms || is_wp_error( $terms ) ) { return ''; }
 usort( $terms, static function ( $a, $b ) { return $a->term_id <=> $b->term_id; } );
 return $terms[0]->name;
}
function cyberdat_editorial_image( $post_id, $hero = false ) {
 $id = get_post_thumbnail_id( $post_id );
 $args = [
  'alt'=>$id ? trim( wp_strip_all_tags( (string)get_post_meta( $id, '_wp_attachment_image_alt', true ) ) ) : '',
  'loading'=>$hero ? 'eager' : 'lazy', 'decoding'=>'async',
  'sizes'=>$hero ? '(min-width: 1440px) 840px, (min-width: 1024px) 62vw, 92vw' : '88px',
 ];
 if ( $hero ) { $args['fetchpriority']='high'; }
 $image = $id ? wp_get_attachment_image( $id, $hero ? 'cyberdat-featured' : 'cyberdat-briefing', false, $args ) : '';
 if ( $image ) { return $image; }
 return sprintf( '<img src="%s" width="1280" height="800" alt="" decoding="async" loading="%s" data-editorial-fallback="true">', esc_url( get_theme_file_uri('/assets/images/editorial-fallback.svg') ), $hero ? 'eager' : 'lazy' );
}
function cyberdat_editorial_test_environment() {
 return ( defined('CYBERDAT_PLAYGROUND') && CYBERDAT_PLAYGROUND ) || in_array( wp_get_environment_type(), ['local','development','staging'], true );
}
