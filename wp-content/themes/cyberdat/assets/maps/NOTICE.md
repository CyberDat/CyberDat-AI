Natural Earth 1:110m land outlines. Public domain.
Source: https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_land.geojson
Terms: https://www.naturalearthdata.com/about/terms-of-use/
Input SHA-256: 9e0729ee253ca7d7a5c4ae9395fb1902264c5377c52e224d13dd85010e2835d9
Derived locally as an equirectangular SVG containing numeric paths only; no tiles, scripts or remote references. Not a claim about political boundaries.

threat-map-countries.json (Global Cyber Threat Map): world-atlas 2.0.2, countries-110m.json (npm package world-atlas,
ISC license, Copyright 2013-2019 Michael Bostock; geometry from Natural Earth 1:110m, public domain).
Source: https://registry.npmjs.org/world-atlas/-/world-atlas-2.0.2.tgz (integrity checked by the build script).
Derived by tools/threat-map/build-geometry.cjs: one numeric SVG path per country, equirectangular, latitude 84..-60,
Antarctica removed, rings across the antimeridian unwrapped. ISO 3166-1 codes and names from iso3166-1.json.
Borders follow UN-recognised boundaries: Crimea is shown as part of Ukraine. Derived from Natural Earth 1:110m.
(Natural Earth draws de facto control; the build script moves the Crimea polygon from Russia to Ukraine, joins
N. Cyprus to Cyprus and Somaliland to Somalia, and keeps Kosovo separate.)
