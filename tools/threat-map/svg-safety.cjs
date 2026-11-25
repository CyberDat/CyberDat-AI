/*
 * Safety check for third-party SVG files served from the theme (country flags of the threat map).
 * A file is accepted only as a self-contained static picture: no scripts, no event handlers, no foreignObject, no
 * references outside the document (href / xlink:href / url() only to "#id"), no embedded images, no styles that
 * can load anything, no DOCTYPE or entities. Used by tools/threat-map/build-flags.cjs and tests/threat-map-flags.test.cjs.
 */
'use strict';

const RULES = [
	['script element', /<script\b/i],
	['event handler attribute', /\son[a-z]+\s*=/i],
	['foreignObject', /<foreignObject\b/i],
	['external href', /\b(?:xlink:)?href\s*=\s*(?:"(?!#)[^"]*"|'(?!#)[^']*')/i],
	['external url()', /url\(\s*(?!["']?#)[^)]*\)/i],
	['embedded image', /<image\b/i],
	['style element', /<style\b/i],
	['@import', /@import/i],
	['DOCTYPE or entity', /<!DOCTYPE|<!ENTITY/i],
	['processing instruction other than xml', /<\?(?!xml\s)/i],
	['javascript: or data: URI', /(?:javascript|data|vbscript):/i],
	['animation element', /<(?:animate|set|animateTransform|animateMotion)\b/i],
];

/** Problems found in an SVG text; an empty list means the file may be included. */
function svgProblems(text) {
	const problems = RULES.filter(([, re]) => re.test(text)).map(([name]) => name);
	if (!/^\s*(?:<\?xml[^>]*\?>\s*)?<svg\b[^>]*\bxmlns="http:\/\/www\.w3\.org\/2000\/svg"/.test(text)) problems.push('not a single <svg> root with the SVG namespace');
	if (!/<\/svg>\s*$/.test(text)) problems.push('content after </svg>');
	return problems;
}

/** Cleaned copy: XML declaration and comments removed (nothing else is rewritten). */
function cleanSvg(text) {
	return text.replace(/^\s*<\?xml[^>]*\?>\s*/, '').replace(/<!--[\s\S]*?-->/g, '').trim() + '\n';
}

module.exports = { svgProblems, cleanSvg, RULES };
