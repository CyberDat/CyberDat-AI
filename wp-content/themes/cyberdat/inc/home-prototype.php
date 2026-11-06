<?php
/** Preview-only editorial components. No API calls or persistent writes. */
defined( 'ABSPATH' ) || exit;
function cyberdat_prototype_url( $post ) {
 return $post instanceof WP_Post ? get_permalink( $post ) : home_url( '/' );
}
function cyberdat_prototype_section( $title, $kicker, $taxonomy, $terms, $archive, $style ) {
 $featured = get_page_by_path( 'identity-boundaries-for-ai-agents', OBJECT, 'post' );
 $query = new WP_Query( [ 'post_type'=>'post', 'post_status'=>'publish', 'posts_per_page'=>3, 'no_found_rows'=>true, 'post__not_in'=>$featured ? [$featured->ID] : [], 'ignore_sticky_posts'=>true, 'tax_query'=>[['taxonomy'=>$taxonomy,'field'=>'slug','terms'=>$terms]] ] );
 if ( ! $query->have_posts() ) { return; }
 $heading = 'section-' . sanitize_html_class( $style );
 ?>
 <section class="home-section section-<?php echo esc_attr( $style ); ?>" aria-labelledby="<?php echo esc_attr( $heading ); ?>"><div class="section-heading-row"><div><p class="eyebrow"><?php echo esc_html( $kicker ); ?></p><h2 id="<?php echo esc_attr( $heading ); ?>"><?php echo esc_html( $title ); ?></h2></div><a class="text-link" href="<?php echo esc_url( home_url( $archive ) ); ?>"><?php esc_html_e( 'Explore', 'cyberdat' ); ?> <span aria-hidden="true">↗</span></a></div><div class="editorial-grid">
 <?php while ( $query->have_posts() ) : $query->the_post(); $categories = get_the_category(); ?>
 <article class="editorial-card"><div class="card-art card-art-<?php echo esc_attr( $style ); ?>" aria-hidden="true"><div class="art-grid"></div><span class="art-node node-a"></span><span class="art-node node-b"></span><span class="art-node node-c"></span><span class="card-art-symbol"><?php echo 'learning' === $style ? '&gt;_' : ( 'ai' === $style ? 'AI' : '//' ); ?></span><span class="card-art-label">CYBERDAT / RESEARCH</span></div><div class="editorial-card-body"><div class="story-meta"><span><?php echo esc_html( $categories ? $categories[0]->name : __( 'Research', 'cyberdat' ) ); ?></span><span class="sample-label">SAMPLE</span></div><h3><a href="<?php the_permalink(); ?>"><?php echo esc_html( get_the_title() ); ?></a></h3><p><?php echo esc_html( wp_trim_words( get_the_excerpt(), 22 ) ); ?></p><div class="card-bottom"><span><?php esc_html_e( 'Preview edition', 'cyberdat' ); ?></span><a href="<?php the_permalink(); ?>" aria-label="<?php echo esc_attr( sprintf( /* translators: %s: Article title. */ __( 'Read: %s', 'cyberdat' ), get_the_title() ) ); ?>">↗</a></div></div></article>
 <?php endwhile; wp_reset_postdata(); ?>
 </div></section>
 <?php
}
