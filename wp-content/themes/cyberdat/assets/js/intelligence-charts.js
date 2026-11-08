/* Cache-only SVG enhancement. No network, libraries, HTML insertion or global state. */
(() => {
 'use strict';
 const ns = 'http://www.w3.org/2000/svg';
 const lineModel = (series, days) => {
  if (![7, 30, 90].includes(days) || !series || Array.isArray(series)) throw new Error('Invalid chart');
  const entries = Object.entries(series).sort(([a], [b]) => a.localeCompare(b));
  if (entries.length !== 90 || entries.some(([date, n]) => !/^\d{4}-\d{2}-\d{2}$/.test(date) || !Number.isInteger(n) || n < 0 || n > 12000)) throw new Error('Invalid series');
  const rows = entries.slice(-days), maximum = Math.max(1, ...rows.map(([, n]) => n));
  return { rows, maximum, total: rows.reduce((sum, [, n]) => sum + n, 0), points: rows.map(([date, count], i) => ({ date, count, x: 44 + 512 * i / Math.max(1, rows.length - 1), y: 174 - 140 * count / maximum })) };
 };
 if (typeof module !== 'undefined' && module.exports) module.exports = { lineModel };
 if (typeof document === 'undefined') return;
 const make = (tag, attrs) => { const node = document.createElementNS(ns, tag); Object.entries(attrs).forEach(([k, v]) => node.setAttribute(k, String(v))); return node; };
 document.querySelectorAll('.td-chart-card').forEach(card => {
  const tooltip = card.querySelector('[data-chart-tooltip]');
  const show = text => { if (tooltip) tooltip.textContent = text; };
  ['pointerover', 'focusin', 'click'].forEach(name => card.addEventListener(name, event => { const target = event.target.closest('[data-tooltip]'); if (target) show(target.dataset.tooltip); }));
  card.addEventListener('keydown', event => { if (event.key === 'Escape') show('Focus, tap or hover a chart mark to inspect its value.'); });
 });
 document.querySelectorAll('[data-chart-line]').forEach(chart => {
  try {
   const series = JSON.parse(chart.dataset.series), svg = chart.querySelector('svg'), plot = chart.querySelector('[data-chart-plot]');
   let model = lineModel(series, 30);
   const label = p => `${p.date} UTC · ${p.count} records`;
   const show = p => { chart.querySelector('[data-chart-tooltip]').textContent = label(p); };
   const draw = days => {
    model = lineModel(series, days);
    const path = make('polyline', { points: model.points.map(p => `${p.x},${p.y}`).join(' '), fill: 'none', stroke: '#70f3cb', 'stroke-width': 2.5, class: 'td-chart-path' });
    plot.replaceChildren(path);
    model.points.forEach(p => { const dot = make('circle', { cx: p.x, cy: p.y, r: 7, class: 'td-chart-point', tabindex: 0, 'data-tooltip': label(p), 'aria-label': label(p) }); const title = make('title', {}); title.textContent = label(p); dot.append(title); plot.append(dot); });
    chart.querySelector('[data-chart-max]').textContent = model.maximum;
    chart.querySelector('[data-chart-first]').textContent = model.rows[0][0];
    chart.querySelector('[data-chart-last]').textContent = model.rows[model.rows.length - 1][0];
    chart.querySelector('[data-chart-description]').textContent = model.rows.map(([d, n]) => `${d}: ${n}`).join('; ');
    chart.querySelector('[data-chart-window]').textContent = `${model.rows[0][0]} → ${model.rows[model.rows.length - 1][0]} · ${model.total} records`;
    chart.querySelectorAll('[data-period]').forEach(b => b.setAttribute('aria-pressed', String(Number(b.dataset.period) === days)));
    chart.dataset.activePeriod = String(days);
    chart.querySelector('[data-chart-tooltip]').textContent = `${days} UTC calendar days · ${model.total} records. Focus, tap or hover to inspect.`;
   };
   chart.querySelectorAll('[data-period]').forEach(button => button.addEventListener('click', () => draw(Number(button.dataset.period))));
   ['pointermove', 'click'].forEach(name => svg.addEventListener(name, event => { const box = svg.getBoundingClientRect(); if (!box.width) return; const x = 600 * (event.clientX - box.left) / box.width; const i = Math.max(0, Math.min(model.points.length - 1, Math.round((x - 44) / 512 * (model.points.length - 1)))); show(model.points[i]); }));
   draw(30); chart.querySelector('.td-chart-controls').hidden = false;
  } catch (_) {
   // Validated server-rendered SVG and the complete accessible table remain usable.
   chart.dataset.enhancement = 'unavailable';
  }
 });
})();
