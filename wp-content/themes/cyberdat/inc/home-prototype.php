<?php
/** Preview-only editorial components. No API calls or persistent writes. */
defined( 'ABSPATH' ) || exit;
function cyberdat_prototype_url( $post ) {
 return $post instanceof WP_Post ? get_permalink( $post ) : home_url( '/' );
}
/** Local responsive original artwork. Empty alt avoids duplicating adjacent headlines. */
function cyberdat_prototype_image( $key, $lazy = true, $thumbnail = false ) {
 $allowed = ['hero','network','identity','detection','model','boundary','learning','intelligence','redteam','foundations'];
 if ( ! in_array( $key, $allowed, true ) ) { $key = 'hero'; }
 $prefix = '/assets/images/premium/' . $key . '-';
 $src = get_theme_file_uri( $prefix . ( $thumbnail ? '192' : ( $lazy ? '640' : '1280' ) ) . '.webp' );
 $srcset = $thumbnail ? $src . ' 192w' : ( $lazy ? get_theme_file_uri( $prefix . '320.webp' ) . ' 320w, ' . get_theme_file_uri( $prefix . '640.webp' ) . ' 640w' : get_theme_file_uri( $prefix . '640.webp' ) . ' 640w, ' . get_theme_file_uri( $prefix . '1280.webp' ) . ' 1280w' );
 $sizes = $thumbnail ? '88px' : ( $lazy ? '(min-width: 1440px) 395px, (min-width: 1024px) 30vw, (min-width: 672px) 44vw, 90vw' : '(min-width: 1440px) 840px, (min-width: 1024px) 62vw, 92vw' );
 ?>
 <img src="<?php echo esc_url( $src ); ?>" srcset="<?php echo esc_attr( $srcset ); ?>" sizes="<?php echo esc_attr( $sizes ); ?>" width="1280" height="800" alt="" decoding="async" <?php if ( $lazy ) : ?>loading="lazy"<?php else : ?>fetchpriority="high"<?php endif; ?>>
 <?php
}
function cyberdat_prototype_section( $title, $kicker, $taxonomy, $terms, $archive, $style ) {
 $curated = [
  'analysis'=>['ai-security-review','security-boundary-analysis','detection-context-analysis'],
  'ai'=>['prompt-boundary-ai','ai-supply-chain-preview','ai-redteam-preview'],
  'learning'=>['network-segmentation-checklist','understanding-threat-intelligence','cybersecurity-foundations'],
 ];
 $art = [
  'ai-security-review'=>'model', 'security-boundary-analysis'=>'network', 'detection-context-analysis'=>'detection',
  'prompt-boundary-ai'=>'boundary', 'ai-supply-chain-preview'=>'identity', 'ai-redteam-preview'=>'redteam',
  'network-segmentation-checklist'=>'learning', 'understanding-threat-intelligence'=>'intelligence', 'cybersecurity-foundations'=>'foundations',
 ];
 $ids=[];
 foreach ( $curated[$style] ?? [] as $slug ) { $item=get_page_by_path( $slug, OBJECT, 'post' ); if ( $item ) { $ids[]=$item->ID; } }
 if ( ! $ids ) { return; }
 $query = new WP_Query( ['post_type'=>'post','post_status'=>'publish','post__in'=>$ids,'orderby'=>'post__in','posts_per_page'=>3,'no_found_rows'=>true,'ignore_sticky_posts'=>true] );
 if ( ! $query->have_posts() ) { return; }
 $heading='section-'.sanitize_html_class( $style );
 ?>
 <section class="home-section section-<?php echo esc_attr( $style ); ?>" aria-labelledby="<?php echo esc_attr( $heading ); ?>"><div class="section-heading-row"><div><p class="eyebrow"><?php echo esc_html( $kicker ); ?></p><h2 id="<?php echo esc_attr( $heading ); ?>"><?php echo esc_html( $title ); ?></h2></div><a class="text-link" href="<?php echo esc_url( home_url( $archive ) ); ?>"><?php esc_html_e( 'Explore', 'cyberdat' ); ?> <span aria-hidden="true">↗</span></a></div><div class="editorial-grid">
 <?php while ( $query->have_posts() ) : $query->the_post(); $categories=get_the_category(); $key=$art[get_post_field('post_name',get_the_ID())] ?? 'hero'; ?>
 <article class="editorial-card"><a class="editorial-image" href="<?php the_permalink(); ?>" tabindex="-1" aria-hidden="true"><?php cyberdat_prototype_image( $key ); ?></a><div class="editorial-card-body"><div class="story-meta"><span><?php echo esc_html( $categories ? $categories[0]->name : __( 'Research', 'cyberdat' ) ); ?></span><span class="sample-label">SAMPLE</span></div><h3><a href="<?php the_permalink(); ?>"><?php echo esc_html( get_the_title() ); ?></a></h3><p><?php echo esc_html( wp_trim_words( get_the_excerpt(), 22 ) ); ?></p><div class="card-bottom"><time datetime="<?php echo esc_attr( get_the_date( DATE_W3C ) ); ?>"><?php echo esc_html( get_the_date( 'M j, Y' ) ); ?></time><a href="<?php the_permalink(); ?>" aria-label="<?php echo esc_attr( sprintf( /* translators: %s: Article title. */ __( 'Read: %s', 'cyberdat' ), get_the_title() ) ); ?>">↗</a></div></div></article>
 <?php endwhile; wp_reset_postdata(); ?>
 </div></section>
 <?php
}
