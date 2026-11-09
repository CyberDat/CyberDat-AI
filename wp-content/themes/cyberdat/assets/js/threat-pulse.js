/* Local DOM/SVG enhancement only: no requests, storage, tracking or external dependencies. */
(function () {
 'use strict';
 function period(series, days) {
  if (![7, 30, 90].includes(days) || !series || Array.isArray(series)) return null;
  const values = Object.entries(series).slice(-days);
  if (values.length !== days || values.some(([date, n], i) => !/^\d{4}-\d{2}-\d{2}$/.test(date) || !Number.isSafeInteger(n) || n < 0 || !Number.isFinite(Date.parse(date + 'T00:00:00Z')) || (i > 0 && Date.parse(date) - Date.parse(values[i - 1][0]) !== 86400000))) return null;
  return { values, total: values.reduce((n, row) => n + row[1], 0), available: values.filter(row => row[1] > 0).length >= 2 };
 }
 function selection(model,days) {
  const value=model?.periods?.[days];
  if(![7,30,90].includes(days)||!value||!['critical','nvd','kev','ransomware'].every(key=>Number.isSafeInteger(value.counts?.[key])&&value.counts[key]>=0))return null;
  return value;
 }
 function points(values) {
  const max = Math.max(1, ...values.map(row => row[1]));
  return values.map((row, i) => [4 + 272 * i / Math.max(1, values.length - 1), 46 - 40 * row[1] / max]);
 }
 if (typeof module !== 'undefined' && module.exports) module.exports = { period, points, selection };
 if (typeof document === 'undefined') return;
 const ns = 'http://www.w3.org/2000/svg';
 document.querySelectorAll('[data-threat-pulse="2.1"]').forEach(root => {
  let periodModel; try { periodModel = JSON.parse(root.dataset.pulsePeriods); } catch (_) { return; }
  if (!periodModel || !periodModel.periods) return;
  const tooltip = root.querySelector('[data-pulse-tooltip]');
  const show = message => { if (tooltip) tooltip.textContent = message; };
  root.querySelectorAll('[data-pulse-tip]').forEach(el => {
   const tip = () => show(el.dataset.pulseTip);
   el.addEventListener('pointerenter', tip); el.addEventListener('focus', tip); el.addEventListener('click', tip);
   el.title = el.dataset.pulseTip;
  });
  const charts = [];
  root.querySelectorAll('[data-pulse-series]').forEach(el => {
   let series; try { series = JSON.parse(el.dataset.pulseSeries); } catch (_) { return; }
   const svg = el.querySelector('svg'), line = svg.querySelector('polyline'), summary = el.querySelector('[data-spark-summary]'), container = el.querySelector('[data-spark-table]');
   const marker = document.createElementNS(ns, 'circle'); marker.setAttribute('r', '3'); marker.setAttribute('fill', '#e7fff7'); marker.setAttribute('visibility', 'hidden'); svg.append(marker);
   let current = null, cursor = 0, plot = [];
   const inspect = index => {
    if (!current || !current.available) return;
    cursor = Math.max(0, Math.min(current.values.length - 1, index));
    const [date, count] = current.values[cursor];
    marker.setAttribute('cx', plot[cursor][0]); marker.setAttribute('cy', plot[cursor][1]); marker.setAttribute('visibility', 'visible');
    show(date + ' UTC · ' + count + ' ' + el.dataset.seriesLabel + (el.dataset.seriesSource === 'nvd' ? ' · partial local index' : ''));
   };
   svg.setAttribute('tabindex', '0');
   svg.addEventListener('focus', () => inspect(cursor));
   svg.addEventListener('keydown', event => { if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) { event.preventDefault(); inspect(event.key === 'Home' ? 0 : event.key === 'End' ? current.values.length - 1 : cursor + (event.key === 'ArrowLeft' ? -1 : 1)); } });
   const pointer = event => { const box = svg.getBoundingClientRect(); if (current && box.width) inspect(Math.round(((event.clientX - box.left) / box.width * 280 - 4) / 272 * (current.values.length - 1))); };
   svg.addEventListener('pointermove', pointer); svg.addEventListener('click', pointer);
   const render = days => {
    current = period(series, days); marker.setAttribute('visibility', 'hidden'); svg.toggleAttribute('hidden', !current || !current.available);
    summary.textContent = current && current.available ? days + ' days · ' + current.total + ' records · UTC daily ' + el.dataset.seriesLabel : 'Insufficient dated observations for a ' + days + '-day trend.';
    if (current) {
     plot = points(current.values); line.setAttribute('points', plot.map(p => p.join(',')).join(' '));
     const title = days + ' days · ' + el.dataset.seriesLabel + ' · ' + current.total + ' indexed records' + (el.dataset.seriesSource === 'nvd' ? ' · partial coverage' : '');
     svg.setAttribute('aria-label', title + '. Use left and right arrow keys to inspect daily counts.'); svg.querySelector('title').textContent = title;
     const table = document.createElement('table'), caption = document.createElement('caption'), head = document.createElement('thead'), header = document.createElement('tr'), body = document.createElement('tbody');
     caption.textContent = title; table.append(caption, head, body); head.append(header);
     ['UTC date', 'Records'].forEach(label => { const th = document.createElement('th'); th.textContent = label; header.append(th); });
     current.values.forEach(([date, count]) => { const row = document.createElement('tr'), th = document.createElement('th'), td = document.createElement('td'); th.textContent = date; td.textContent = count; row.append(th, td); body.append(row); });
     container.replaceChildren(table); cursor = current.values.length - 1;
    } else { container.textContent = 'No validated daily series is available for this period.'; }
   };
   charts.push(render); render(7);
  });
  const controls = root.querySelector('.tp-periods');
  if (charts.length && controls) {
   controls.hidden = false;
   controls.querySelectorAll('[data-pulse-period]').forEach(button => button.addEventListener('click', () => {
    const days = Number(button.dataset.pulsePeriod); if (![7, 30, 90].includes(days)) return;
    const chosen = selection(periodModel,days); if (!chosen) return;
    root.querySelectorAll('[data-pulse-kpi]').forEach(card => { const key = card.dataset.pulseKpi === 'nvd_7' ? 'nvd' : card.dataset.pulseKpi; const value = chosen.counts[key]; card.dataset.value = String(value); card.querySelector('[data-pulse-number]').textContent = Number(value).toLocaleString('en-US'); const scopes={critical:'current selected CVSS 9.0–10.0 · partial NVD',nvd:'NVD publication dates · partial index',kev:'CISA dateAdded',ransomware:'CISA dateAdded · ransomware use Known'};card.querySelector('[data-pulse-scope]').textContent=days+' UTC calendar days · '+scopes[key]; });
    root.querySelector('[data-pulse-window]').textContent = chosen.start + ' → ' + chosen.end + ' UTC · ' + days + ' days';
    charts.forEach(render => render(days)); controls.querySelectorAll('button').forEach(b => b.setAttribute('aria-pressed', String(b === button)));
    show('Daily trends: ' + days + ' days. All four headline KPIs use this period. CVSS breakdown remains all indexed dates; NVD coverage is partial.');
   }));
  }
 });
}());
