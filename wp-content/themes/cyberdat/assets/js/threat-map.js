/* Global Cyber Threat Map: counts embedded in the page + country shapes from the theme. Same origin only; no
 * request ever goes to a data source, a CDN or a tile server. */
(() => {
	'use strict';
	const STEPS = 5;
	const STALE_AFTER = 10800, UNAVAILABLE_AFTER = 172800;

	/** Lower bounds of the colour steps 1..5 on a geometric scale from 1 to max (strictly increasing, all <= max). */
	const edges = max => {
		const out = [];
		if (!(max > 0)) return out;
		for (let i = 0; i < STEPS; i++) {
			const e = Math.max(out.length ? out[out.length - 1] + 1 : 1, Math.round(Math.pow(max, i / (STEPS - 1))));
			if (e > max) break;
			out.push(e);
		}
		return out;
	};
	const step = (v, e) => { let s = 0; for (let i = 0; i < e.length; i++) if (v >= e[i]) s = i + 1; return v > 0 ? s : 0; };
	const fmt = n => Number(n).toLocaleString('en-US');
	const legend = (e, max) => e.map((from, i) => {
		const to = i + 1 < e.length ? e[i + 1] - 1 : max;
		return { step: i + 1, label: from === to ? fmt(from) : fmt(from) + '–' + fmt(to) };
	});
	/** Change against the previous period; null when there is no comparable previous period. */
	const delta = (n, prev) => {
		if (typeof prev !== 'number') return null;
		if (prev === 0) return n > 0 ? { text: 'new', dir: 'up' } : { text: '0', dir: '' };
		const p = Math.round((n - prev) / prev * 100);
		return { text: (p > 0 ? '+' : '') + p + '%', dir: p > 0 ? 'up' : p < 0 ? 'down' : '' };
	};
	const ago = s => {
		const m = Math.floor(Math.max(0, s) / 60);
		if (m < 1) return 'less than a minute ago';
		if (m < 60) return m + ' min ago';
		const h = Math.floor(m / 60);
		return h < 48 ? h + ' h ' + (m % 60) + ' min ago' : Math.floor(h / 24) + ' days ago';
	};
	const utc = t => new Date(t * 1000).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
	const freshness = (last, now) => typeof last !== 'number' ? 'unavailable' : now - last <= STALE_AFTER ? 'ok' : now - last <= UNAVAILABLE_AFTER ? 'stale' : 'unavailable';
	const recordsUrl = (tpl, cc) => {
		try { const u = new URL(String(tpl).replace('{CC}', encodeURIComponent(cc))); return u.protocol === 'https:' && !u.username && !u.password ? u.href : null; } catch (_) { return null; }
	};
	if (typeof module !== 'undefined' && module.exports) module.exports = { edges, step, legend, delta, ago, freshness, recordsUrl };
	if (typeof document === 'undefined') return;

	const root = document.querySelector('[data-threat-map="cdtm-1"]');
	if (!root) return;
	let data;
	try { data = JSON.parse(root.querySelector('[data-cdtm-data]').textContent); } catch (_) { return; }
	if (!data || data.schema !== 1 || !data.layers) return;
	const $ = s => root.querySelector(s);
	const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text !== undefined) n.textContent = text; return n; };
	const loadedAt = Date.now();
	const serverNow = () => data.now + Math.floor((Date.now() - loadedAt) / 1000);
	const stage = $('[data-cdtm-stage]'), mapBox = $('[data-cdtm-map]'), tip = $('[data-cdtm-tip]'), legendBox = $('[data-cdtm-legend]');
	const countryBox = $('[data-cdtm-country]'), topList = $('[data-cdtm-top]'), topTitle = $('[data-cdtm-top-title]'), topEmpty = $('[data-cdtm-top-empty]');
	const search = $('[data-cdtm-search]'), results = $('[data-cdtm-results]'), unitLine = $('[data-cdtm-unit]');
	const tabs = [...root.querySelectorAll('[data-cdtm-tab]')], periods = [...root.querySelectorAll('[data-cdtm-period]')];
	const placeholder = [...countryBox.childNodes].map(node => node.cloneNode(true));
	const wide = window.matchMedia('(min-width: 641px)');
	const state = { layer: tabs.find(t => t.getAttribute('aria-selected') === 'true')?.dataset.cdtmTab || Object.keys(data.layers)[0], period: data.period, selected: null };
	let paths = null, geometryRequested = false;

	const layer = () => data.layers[state.layer];
	const periodData = () => { const l = layer(); return l.periods ? l.periods[state.period] : null; };
	const geoNames = new Map();
	const name = cc => data.names[cc] || geoNames.get(cc) || cc;
	const rows = () => { const p = periodData(); return p ? Object.entries(p.countries).map(([cc, r]) => ({ cc, ...r })) : []; };

	const renderTop = () => {
		const l = layer(), all = rows().filter(r => r.n > 0), top = all.slice(0, 10), max = top.length ? top[0].n : 1;
		topTitle.textContent = 'Top 10 countries · ' + data.labels[state.period];
		topList.replaceChildren(...top.map((r, i) => {
			const li = el('li'), b = el('button'); b.type = 'button'; b.dataset.cdtmCc = r.cc;
			if (state.selected === r.cc) b.setAttribute('aria-current', 'true');
			const label = el('span', 'cdtm-top-name'), bar = el('span', 'cdtm-bar'), fill = el('span');
			fill.style.width = Math.max(3, Math.round(r.n / max * 100)) + '%'; bar.append(fill); label.append(el('span', '', name(r.cc)), bar);
			b.append(el('span', 'cdtm-rank', String(i + 1)), label, el('span', 'cdtm-top-n', fmt(r.n)));
			b.setAttribute('aria-label', (i + 1) + '. ' + name(r.cc) + ': ' + fmt(r.n) + ' ' + l.unit);
			li.append(b); return li;
		}));
		topEmpty.hidden = top.length > 0;
		topEmpty.textContent = l.periods && Object.keys(l.periods).length ? 'No country totals in this period.' : 'No data to show for this layer.';
	};

	const renderSearch = () => {
		const q = search.value.trim().toLowerCase();
		if (!q) { results.replaceChildren(); return; }
		const l = layer(), hits = rows().filter(r => r.n > 0 && (name(r.cc).toLowerCase().includes(q) || r.cc.toLowerCase() === q)).slice(0, 30);
		results.replaceChildren(...(hits.length ? hits.map(r => {
			const li = el('li'), b = el('button'); b.type = 'button'; b.dataset.cdtmCc = r.cc;
			b.append(el('span', 'cdtm-rank', r.cc), el('span', '', name(r.cc)), el('span', 'cdtm-top-n', fmt(r.n)));
			b.setAttribute('aria-label', name(r.cc) + ': ' + fmt(r.n) + ' ' + l.unit);
			li.append(b); return li;
		}) : [el('li', 'cdtm-note', 'No country with data matches.')]));
	};

	const renderCountry = () => {
		const cc = state.selected, l = layer(), p = periodData();
		if (!cc) { countryBox.replaceChildren(...placeholder.map(node => node.cloneNode(true))); return; }
		const r = p && p.countries[cc] ? p.countries[cc] : { n: 0, b: [] };
		const head = el('div', 'cdtm-country-head'), titles = el('div');
		titles.append(el('p', 'cdtm-kicker', 'SELECTED COUNTRY · ' + data.labels[state.period].toUpperCase()), el('h4', '', name(cc)));
		const close = el('button', 'cdtm-close', '×'); close.type = 'button'; close.setAttribute('aria-label', 'Close country details');
		close.addEventListener('click', () => { const back = state.selected; select(null); const t = root.querySelector('[data-cdtm-cc="' + back + '"]'); (t || tabs[0]).focus(); });
		head.append(titles, close);
		const figures = el('div', 'cdtm-figures'), total = el('div'), change = el('div');
		total.append(el('span', '', l.unit.charAt(0).toUpperCase() + l.unit.slice(1)), el('strong', '', fmt(r.n)));
		const d = p && p.comparable ? delta(r.n, typeof r.prev === 'number' ? r.prev : 0) : null;
		change.append(el('span', '', 'vs previous period'));
		if (d) { const s = el('strong', d.dir ? 'cdtm-' + d.dir : '', d.text); change.append(s); if (typeof r.prev === 'number') change.append(el('span', '', 'previous: ' + fmt(r.prev))); }
		else change.append(el('strong', '', '—'), el('span', '', l.history_since ? 'Collecting data since ' + utc(l.history_since).slice(0, 10) : 'No comparison yet'));
		figures.append(total, change);
		const parts = [head, figures];
		if (r.b && r.b.length) {
			parts.push(el('p', 'cdtm-kicker', l.breakdown.toUpperCase()));
			const ul = el('ul', 'cdtm-breakdown');
			for (const [label, n] of r.b) { const li = el('li'); li.append(el('span', '', label), el('span', '', fmt(n))); ul.append(li); }
			parts.push(ul);
		}
		const links = el('div', 'cdtm-links'), url = recordsUrl(l.records_url, cc);
		if (url) { const a = el('a', '', l.records_label + ' ↗'); a.href = url; a.rel = 'noopener noreferrer'; links.append(a); }
		parts.push(links);
		const related = el('section', 'cdtm-related'); related.setAttribute('aria-label', 'Related CyberDat articles'); related.dataset.cdtmRelated = cc;
		related.append(el('h5', '', 'Related CyberDat articles'), el('p', 'cdtm-note', 'Not linked yet.'));
		parts.push(related);
		countryBox.replaceChildren(...parts);
	};

	const paint = () => {
		const p = periodData(), max = rows().reduce((m, r) => Math.max(m, r.n), 0), e = edges(max);
		stage.dataset.state = p ? 'data' : 'nodata';
		if (paths) for (const [cc, path] of paths) {
			const r = p && p.countries[cc], v = r ? r.n : 0;
			path.setAttribute('class', 'cdtm-c s' + (p ? step(v, e) : 0) + (state.selected === cc ? ' is-selected' : ''));
		}
		const items = [{ step: 0, label: p ? 'none' : 'no data' }, ...(p ? legend(e, max) : [])];
		legendBox.replaceChildren(el('span', '', layer().unit.charAt(0).toUpperCase() + layer().unit.slice(1) + ':'), ...items.map(x => {
			const s = el('span'), sw = el('i'); sw.style.background = 'var(--cdtm-s' + x.step + ')'; s.append(sw, document.createTextNode(x.label)); return s;
		}));
	};

	const render = () => {
		unitLine.textContent = layer().unit.charAt(0).toUpperCase() + layer().unit.slice(1) + ' · ' + data.labels[state.period];
		const panel = root.querySelector('[data-cdtm-panel="' + state.layer + '"]');
		const p = periodData(), collecting = panel.querySelector('[data-cdtm-collecting]');
		collecting.textContent = p && !p.comparable && layer().history_since ? 'Collecting data since ' + utc(layer().history_since).slice(0, 10) + '; no comparison with the previous period yet.' : '';
		paint(); renderTop(); renderSearch(); renderCountry();
	};

	const select = cc => {
		// the lists are rebuilt: keep keyboard focus on the same country's button in the same list
		const active = document.activeElement, list = active && active.dataset && active.dataset.cdtmCc ? active.closest('[data-cdtm-top],[data-cdtm-results]') : null;
		const keep = list ? active.dataset.cdtmCc : null;
		state.selected = cc; paint(); renderTop(); renderSearch(); renderCountry();
		if (list) { const again = list.querySelector('[data-cdtm-cc="' + keep + '"]'); if (again) again.focus(); }
	};

	const showLayer = (id, focus) => {
		state.layer = id; state.selected = null;
		for (const t of tabs) t.setAttribute('aria-selected', String(t.dataset.cdtmTab === id));
		for (const panel of root.querySelectorAll('[data-cdtm-panel]')) {
			const on = panel.dataset.cdtmPanel === id; panel.hidden = !on;
			if (on) panel.querySelector('[data-cdtm-slot]').append(stage);
		}
		render();
		if (focus) tabs.find(t => t.dataset.cdtmTab === id).focus();
	};

	const buildMap = geo => {
		if (!geo || geo.schema !== 1 || !Array.isArray(geo.countries)) throw new Error('geometry');
		const NS = 'http://www.w3.org/2000/svg', svg = document.createElementNS(NS, 'svg');
		svg.setAttribute('viewBox', geo.viewBox); svg.setAttribute('aria-hidden', 'true'); svg.setAttribute('focusable', 'false');
		paths = new Map();
		for (const c of geo.countries) {
			const path = document.createElementNS(NS, 'path'); path.setAttribute('d', c.d);
			if (c.iso && /^[A-Z]{2}$/.test(c.iso)) { path.dataset.cc = c.iso; paths.set(c.iso, path); geoNames.set(c.iso, String(c.name)); } else path.setAttribute('class', 'cdtm-x');
			svg.append(path);
		}
		mapBox.replaceChildren(svg);
		const value = cc => { const r = periodData() && periodData().countries[cc]; return r ? r.n : 0; };
		let hover = null;
		svg.addEventListener('pointermove', ev => {
			const cc = ev.target.dataset && ev.target.dataset.cc;
			if (hover && hover !== ev.target) hover.classList.remove('is-hover');
			if (!cc) { tip.hidden = true; hover = null; return; }
			hover = ev.target; hover.classList.add('is-hover');
			const box = mapBox.getBoundingClientRect(), v = value(cc), l = layer();
			tip.replaceChildren(el('strong', '', name(cc)), el('span', '', periodData() ? (v ? fmt(v) + ' ' + l.unit : 'none reported') : 'no data'));
			tip.hidden = false;
			const x = Math.min(ev.clientX - box.left + 14, box.width - tip.offsetWidth - 4), y = Math.min(ev.clientY - box.top + 14, box.height - tip.offsetHeight + 40);
			tip.style.left = Math.max(4, x) + 'px'; tip.style.top = Math.max(4, y) + 'px';
		});
		svg.addEventListener('pointerleave', () => { tip.hidden = true; if (hover) hover.classList.remove('is-hover'); hover = null; });
		svg.addEventListener('click', ev => { const cc = ev.target.dataset && ev.target.dataset.cc; if (cc) select(cc); });
		paint();
	};

	const loadGeometry = () => {
		if (geometryRequested || !wide.matches) return;
		geometryRequested = true;
		const url = new URL(root.dataset.geometry, location.href);
		if (url.origin !== location.origin) return;
		fetch(url.href, { credentials: 'same-origin', redirect: 'error', headers: { Accept: 'application/json' } })
			.then(r => { if (!r.ok) throw new Error('geometry'); return r.json(); })
			.then(buildMap)
			.catch(() => { mapBox.replaceChildren(el('p', 'cdtm-note', 'The map could not be loaded. The top 10 list and the country search still work.')); });
	};

	const refreshStatus = () => {
		const now = serverNow();
		for (const panel of root.querySelectorAll('[data-cdtm-panel][data-updated]')) {
			const last = Number(panel.dataset.updated), f = freshness(last, now), line = panel.querySelector('[data-cdtm-status]');
			if (panel.dataset.status !== 'ok' && panel.dataset.status !== 'stale') continue;
			line.className = 'cdtm-status cdtm-status--' + f;
			line.textContent = f === 'ok' ? 'Updated ' + ago(now - last) + ' (' + utc(last) + ').'
				: f === 'stale' ? 'Stale: last successful update ' + ago(now - last) + ' (' + utc(last) + '). Collection is retrying.'
				: 'Data unavailable since ' + utc(last) + '. Reload the page for current data.';
		}
	};

	tabs.forEach((t, i) => {
		t.addEventListener('click', () => showLayer(t.dataset.cdtmTab, false));
		t.addEventListener('keydown', ev => {
			const k = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 }[ev.key];
			if (k === undefined) return;
			ev.preventDefault(); showLayer(tabs[(k + tabs.length) % tabs.length].dataset.cdtmTab, true);
		});
	});
	periods.forEach(b => b.addEventListener('click', () => {
		state.period = b.dataset.cdtmPeriod;
		for (const x of periods) x.setAttribute('aria-pressed', String(x === b));
		render();
	}));
	root.addEventListener('click', ev => { const b = ev.target.closest && ev.target.closest('button[data-cdtm-cc]'); if (b && root.contains(b)) select(b.dataset.cdtmCc); });
	root.addEventListener('keydown', ev => { if (ev.key === 'Escape' && state.selected) { const back = state.selected; select(null); const t = root.querySelector('[data-cdtm-cc="' + back + '"]'); if (t) t.focus(); } });
	search.addEventListener('input', renderSearch);
	if (wide.addEventListener) wide.addEventListener('change', loadGeometry);
	render();
	loadGeometry();
	refreshStatus();
	setInterval(refreshStatus, 60000);
})();
