<?php
/** Global Cyber Threat Map block of the Threat Intelligence page (inc/threat-map.php). */
defined('ABSPATH') || exit;
echo cyberdat_threat_map_render(cyberdat_threat_map_snapshot(), time()); // phpcs:ignore WordPress.Security.EscapeOutput -- escaped in the renderer
