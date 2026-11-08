<?php
/** Native Pages: portable editorial content, fail-closed tool publication. */
defined( 'ABSPATH' ) || exit;

function cyberdat_tool_fields() {
	return array( 'summary', 'how_it_works', 'documentation', 'examples', 'faq', 'github' );
}

function cyberdat_tool_sanitize( $value ) {
	$value = is_array( $value ) ? $value : array();
	$clean = array( 'reviewed' => ! empty( $value['reviewed'] ) );
	foreach ( cyberdat_tool_fields() as $key ) {
		$raw = isset( $value[ $key ] ) && is_string( $value[ $key ] ) ? $value[ $key ] : '';
		$clean[ $key ] = in_array( $key, array( 'summary', 'github' ), true ) ? sanitize_text_field( $raw ) : wp_kses_post( $raw );
	}
	$url = wp_parse_url( $clean['github'] );
	if ( ! is_array( $url ) || 'https' !== ( $url['scheme'] ?? '' ) || 'github.com' !== ( $url['host'] ?? '' ) || isset( $url['user'] ) || isset( $url['pass'] ) ) {
		$clean['github'] = '';
	}
	return $clean;
}

function cyberdat_tool_meta_authorized( $allowed, $key, $post_id ) {
	return current_user_can( 'edit_post', $post_id );
}

function cyberdat_register_tool_meta() {
	$properties = array( 'reviewed' => array( 'type' => 'boolean' ) );
	foreach ( cyberdat_tool_fields() as $key ) {
		$properties[ $key ] = array( 'type' => 'string' );
	}
	register_post_meta( 'page', '_cyberdat_tool', array(
		'type' => 'object', 'single' => true, 'default' => array(),
		'sanitize_callback' => 'cyberdat_tool_sanitize', 'auth_callback' => 'cyberdat_tool_meta_authorized',
		'show_in_rest' => array( 'schema' => array( 'type' => 'object', 'properties' => $properties, 'additionalProperties' => false ) ),
	) );
}
add_action( 'init', 'cyberdat_register_tool_meta' );

function cyberdat_is_tool( $post_id ) {
	return 'page-templates/tool.php' === get_page_template_slug( $post_id );
}

function cyberdat_tool_data( $post_id ) {
	return cyberdat_tool_sanitize( get_post_meta( $post_id, '_cyberdat_tool', true ) );
}

/** Renderers are PHP callbacks registered by reviewed code, never by REST/meta. */
function cyberdat_tool_renderer( $post_id ) {
	$renderer = apply_filters( 'cyberdat/tool/renderer', null, $post_id );
	return is_callable( $renderer ) ? $renderer : null;
}

function cyberdat_tool_ready( $post_id ) {
	$post = get_post( $post_id );
	if ( ! $post || ! cyberdat_is_tool( $post_id ) || $post->post_password || ! cyberdat_tool_renderer( $post_id ) ) {
		return false;
	}
	$data = cyberdat_tool_data( $post_id );
	foreach ( array( 'summary', 'how_it_works', 'documentation', 'examples', 'faq' ) as $key ) {
		if ( '' === trim( wp_strip_all_tags( $data[ $key ] ) ) ) {
			return false;
		}
	}
	return $data['reviewed'];
}

function cyberdat_tool_metabox() {
	add_meta_box( 'cyberdat-tool', __( 'CyberDat Tool — editorial review', 'cyberdat' ), 'cyberdat_tool_metabox_html', 'page', 'normal' );
}
add_action( 'add_meta_boxes', 'cyberdat_tool_metabox' );

function cyberdat_tool_metabox_html( $post ) {
	$data = cyberdat_tool_data( $post->ID );
	wp_nonce_field( 'cyberdat_tool_save', 'cyberdat_tool_nonce' );
	echo '<p>' . esc_html__( 'Used by the Tool template. Save content first; publication requires a reviewed implementation and all content sections. No renderer is shipped in 0.7.', 'cyberdat' ) . '</p>';
	$labels = array( 'summary' => __( 'Short description', 'cyberdat' ), 'how_it_works' => __( 'How It Works', 'cyberdat' ), 'documentation' => __( 'Technical Documentation', 'cyberdat' ), 'examples' => __( 'Examples & Use Cases', 'cyberdat' ), 'faq' => __( 'FAQ (visible HTML; use headings for questions)', 'cyberdat' ), 'github' => __( 'GitHub Source Code URL (optional)', 'cyberdat' ) );
	foreach ( $labels as $key => $label ) {
		echo '<p><label for="cyberdat-tool-' . esc_attr( $key ) . '">' . esc_html( $label ) . '</label><br><textarea class="widefat" rows="3" id="cyberdat-tool-' . esc_attr( $key ) . '" name="cyberdat_tool[' . esc_attr( $key ) . ']">' . esc_textarea( $data[ $key ] ) . '</textarea></p>';
	}
	echo '<p><label><input type="checkbox" name="cyberdat_tool[reviewed]" value="1" ' . checked( $data['reviewed'], true, false ) . '> ' . esc_html__( 'Implementation and expert content reviewed', 'cyberdat' ) . '</label></p>';
}

function cyberdat_tool_save( $post_id ) {
	if ( ! isset( $_POST['cyberdat_tool_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['cyberdat_tool_nonce'] ) ), 'cyberdat_tool_save' ) || ! current_user_can( 'edit_post', $post_id ) || wp_is_post_revision( $post_id ) || wp_is_post_autosave( $post_id ) ) {
		return;
	}
	update_post_meta( $post_id, '_cyberdat_tool', cyberdat_tool_sanitize( isset( $_POST['cyberdat_tool'] ) ? wp_unslash( $_POST['cyberdat_tool'] ) : array() ) );
}
add_action( 'save_post_page', 'cyberdat_tool_save' );

/** REST, editor and WP-CLI all fail closed until saved data and code are ready. */
function cyberdat_tool_publication_guard( $data, $postarr ) {
	$id = isset( $postarr['ID'] ) ? (int) $postarr['ID'] : 0;
	$template = $postarr['page_template'] ?? ( $postarr['meta_input']['_wp_page_template'] ?? ( $id ? get_page_template_slug( $id ) : '' ) );
	if ( 'page' === $data['post_type'] && 'page-templates/tool.php' === $template && in_array( $data['post_status'], array( 'publish', 'future' ), true ) && ( ! $id || ! cyberdat_tool_ready( $id ) ) ) {
		$data['post_status'] = 'draft';
	}
	return $data;
}
add_filter( 'wp_insert_post_data', 'cyberdat_tool_publication_guard', 10, 2 );

function cyberdat_tool_request_guard() {
	$id = get_queried_object_id();
	if ( is_singular( 'page' ) && cyberdat_is_tool( $id ) && ! cyberdat_tool_ready( $id ) && ! ( is_preview() && current_user_can( 'edit_post', $id ) ) ) {
		global $wp_query;
		$wp_query->set_404();
		status_header( 404 );
		nocache_headers();
	}
}
add_action( 'template_redirect', 'cyberdat_tool_request_guard', 1 );

function cyberdat_ready_tools() {
	$query = new WP_Query( array( 'post_type' => 'page', 'post_status' => 'publish', 'has_password' => false, 'posts_per_page' => 100, 'orderby' => array( 'title' => 'ASC', 'ID' => 'ASC' ), 'meta_key' => '_wp_page_template', 'meta_value' => 'page-templates/tool.php', 'no_found_rows' => true ) );
	return array_values( array_filter( $query->posts, static function ( $post ) { return cyberdat_tool_ready( $post->ID ); } ) );
}

function cyberdat_tools_excluded( $post_id ) {
	if ( cyberdat_is_tool( $post_id ) ) {
		return ! cyberdat_tool_ready( $post_id );
	}
	return 'page-templates/tools.php' === get_page_template_slug( $post_id ) && ! cyberdat_ready_tools();
}

function cyberdat_tools_robots( $robots ) {
	if ( is_singular( 'page' ) && cyberdat_tools_excluded( get_queried_object_id() ) ) {
		unset( $robots['index'] );
		$robots['noindex'] = true;
	}
	return $robots;
}
add_filter( 'wp_robots', 'cyberdat_tools_robots', 99 );
add_filter( 'rank_math/frontend/robots', static function ( $robots ) {
	if ( 'staging' === wp_get_environment_type() ) {
		$robots['index'] = 'noindex';
		$robots['follow'] = 'nofollow';
		return $robots;
	}
	if ( is_singular( 'page' ) && cyberdat_tools_excluded( get_queried_object_id() ) ) {
		$robots['index'] = 'noindex';
	}
	return $robots;
}, 99 );
add_filter( 'rank_math/sitemap/entry', static function ( $url, $type, $object ) {
	return 'post' === $type && isset( $object->ID ) && cyberdat_tools_excluded( $object->ID ) ? false : $url;
}, 10, 3 );
add_filter( 'wp_sitemaps_posts_query_args', static function ( $args, $post_type ) {
	if ( 'page' === $post_type ) {
		$pages = get_posts( array( 'post_type' => 'page', 'post_status' => 'publish', 'posts_per_page' => -1, 'fields' => 'ids', 'meta_key' => '_wp_page_template', 'meta_value' => array( 'page-templates/tool.php', 'page-templates/tools.php' ), 'meta_compare' => 'IN' ) );
		$args['post__not_in'] = array_values( array_unique( array_merge( $args['post__not_in'] ?? array(), array_filter( $pages, 'cyberdat_tools_excluded' ) ) ) );
	}
	return $args;
}, 10, 2 );

/** Refine an existing Rank Math entity; never create an independent graph. */
add_filter( 'rank_math/snippet/rich_snippet_article_entity', static function ( $entity ) {
	$id = get_queried_object_id();
	if ( ! is_singular( 'post' ) || 'publish' !== get_post_status( $id ) || get_post_meta( $id, '_cyberdat_staging_fixture', true ) || empty( $entity['headline'] ) || empty( $entity['datePublished'] ) || empty( $entity['author'] ) ) {
		return $entity;
	}
	if ( in_array( $entity['@type'] ?? '', array( 'Article', 'BlogPosting', 'NewsArticle' ), true ) ) {
		$entity['@type'] = has_term( 'news', 'editorial_format', $id ) ? 'NewsArticle' : 'Article';
	}
	return $entity;
}, 20 );

function cyberdat_tools_assets() {
	if ( is_page_template( array( 'page-templates/tool.php', 'page-templates/tools.php' ) ) ) {
		wp_enqueue_style( 'cyberdat-tools', get_template_directory_uri() . '/assets/css/tools.css', array( 'cyberdat-main' ), cyberdat_theme_asset_version( '/assets/css/tools.css' ) );
	}
}
add_action( 'wp_enqueue_scripts', 'cyberdat_tools_assets' );

/** Visible HTML only. Rank Math remains sole owner of schema and SEO tags. */
function cyberdat_tools_breadcrumbs() {
	if ( function_exists( 'rank_math_the_breadcrumbs' ) && class_exists( '\RankMath\Helper' ) && \RankMath\Helper::get_settings( 'general.breadcrumbs' ) ) {
		rank_math_the_breadcrumbs();
		return;
	}
	echo '<nav aria-label="' . esc_attr__( 'Breadcrumbs', 'cyberdat' ) . '"><ol class="cyberdat-tool-breadcrumbs"><li><a href="' . esc_url( home_url( '/' ) ) . '">' . esc_html__( 'Home', 'cyberdat' ) . '</a></li>';
	$hub = get_page_by_path( 'tools' );
	if ( $hub && 'publish' === $hub->post_status && get_the_ID() !== $hub->ID ) {
		echo '<li><a href="' . esc_url( get_permalink( $hub ) ) . '">' . esc_html__( 'Tools', 'cyberdat' ) . '</a></li>';
	}
	echo '<li aria-current="page">' . esc_html( get_the_title() ) . '</li></ol></nav>';
}

function cyberdat_tool_related_links() {
	echo '<nav class="cyberdat-tool-related" aria-label="' . esc_attr__( 'Related reading', 'cyberdat' ) . '"><h2>' . esc_html__( 'Related Tools & Reading', 'cyberdat' ) . '</h2><ul>';
	foreach ( array( 'guides' => __( 'Guides', 'cyberdat' ), 'learning' => __( 'Learning', 'cyberdat' ), 'analysis' => __( 'Analysis', 'cyberdat' ) ) as $slug => $label ) {
		$term = get_term_by( 'slug', $slug, 'editorial_format' );
		if ( $term ) {
			$url = get_term_link( $term );
			if ( ! is_wp_error( $url ) ) {
				echo '<li><a href="' . esc_url( $url ) . '">' . esc_html( $label ) . '</a></li>';
			}
		}
	}
	foreach ( cyberdat_ready_tools() as $tool ) {
		if ( get_the_ID() !== $tool->ID ) {
			echo '<li><a href="' . esc_url( get_permalink( $tool ) ) . '">' . esc_html( get_the_title( $tool ) ) . '</a></li>';
		}
	}
	echo '</ul></nav>';
}

function cyberdat_tools_hub_link() {
	$hub = get_page_by_path( 'tools' );
	if ( $hub && 'publish' === $hub->post_status ) {
		echo '<p><a href="' . esc_url( get_permalink( $hub ) ) . '">' . esc_html__( 'Explore CyberDat Tools', 'cyberdat' ) . '</a></p>';
	}
}
