<?php
/** Editorial section queries and presentation; no taxonomy or SEO registration. */
defined( 'ABSPATH' ) || exit;

/** Up to three public stories; overlap between sections is intentional. */
function cyberdat_section_posts( $taxonomy, $terms, $featured_id = 0 ) {
 if ( ! in_array( $taxonomy, ['category', 'editorial_format'], true ) || ! taxonomy_exists( $taxonomy ) ) { return []; }
 $query = new WP_Query( [
  'post_type'=>'post', 'post_status'=>'publish', 'has_password'=>false,
  'posts_per_page'=>3, 'orderby'=>['date'=>'DESC', 'ID'=>'DESC'],
  'ignore_sticky_posts'=>true, 'no_found_rows'=>true, 'cache_results'=>false,
  'post__not_in'=>$featured_id ? [(int) $featured_id] : [],
  'tax_query'=>[['taxonomy'=>$taxonomy, 'field'=>'slug', 'terms'=>$terms, 'operator'=>'IN', 'include_children'=>false]],
 ] );
 return $query->posts;
}

/** WordPress supplies attachment alt, dimensions and responsive sources. */
function cyberdat_section_image( $post_id ) {
 $id = get_post_thumbnail_id( $post_id );
 $image = $id ? wp_get_attachment_image( $id, 'cyberdat-card', false, [
  'alt'=>trim( wp_strip_all_tags( (string) get_post_meta( $id, '_wp_attachment_image_alt', true ) ) ),
  'loading'=>'lazy', 'decoding'=>'async',
  'sizes'=>'(min-width: 1440px) 395px, (min-width: 1024px) 30vw, (min-width: 672px) 44vw, 90vw',
 ] ) : '';
 if ( $image ) { return $image; }
 return sprintf( '<img src="%s" width="640" height="400" alt="" loading="lazy" decoding="async" data-editorial-fallback="true">', esc_url( get_theme_file_uri( '/assets/images/editorial-fallback.svg' ) ) );
}

function cyberdat_editorial_section( $title, $kicker, $taxonomy, $terms, $archive, $style ) {
 $featured = cyberdat_featured_story();
 $posts = cyberdat_section_posts( $taxonomy, $terms, $featured ? $featured->ID : 0 );
 if ( ! $posts && ! cyberdat_editorial_test_environment() ) { return; }
 $heading = 'section-' . sanitize_html_class( $style );
 ?>
 <section class="home-section section-<?php echo esc_attr( $style ); ?>" aria-labelledby="<?php echo esc_attr( $heading ); ?>"><div class="section-heading-row"><div><p class="eyebrow"><?php echo esc_html( $kicker ); ?></p><h2 id="<?php echo esc_attr( $heading ); ?>"><?php echo esc_html( $title ); ?></h2></div><a class="text-link" href="<?php echo esc_url( home_url( $archive ) ); ?>"><?php esc_html_e( 'Explore', 'cyberdat' ); ?> <span aria-hidden="true">↗</span></a></div><div class="editorial-grid">
 <?php foreach ( $posts as $story ) { get_template_part( 'template-parts/home/editorial-card', null, ['story'=>$story] ); } ?>
 <?php if ( ! $posts ) : ?><p class="editorial-empty"><?php esc_html_e( 'No published stories in this section yet.', 'cyberdat' ); ?></p><?php endif; ?>
 </div></section>
 <?php
}
