const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(__dirname + '/../wp-content/themes/cyberdat/assets/js/tools-filter.js', 'utf8');
const roadmap = JSON.parse(fs.readFileSync(__dirname + '/../wp-content/themes/cyberdat/inc/tools-catalog.json', 'utf8'));
const categories = ['all', ...new Set(roadmap.map(t => t.category_slug))];
const buttons = categories.map(category => ({ dataset: { toolsFilter: category }, attrs: {}, setAttribute(k,v) { this.attrs[k] = v; } }));
const cards = roadmap.map(t => ({ dataset: { toolCategory: t.category_slug }, hidden: false }));
let handler;
const controls = { hidden: true, querySelectorAll: () => buttons, contains: b => buttons.includes(b), addEventListener: (name, fn) => { assert.equal(name, 'click'); handler = fn; } };
const count = { dataset: { countLabel: 'tools shown' }, textContent: '' };
const catalog = { querySelector: key => key === '[data-tools-filters]' ? controls : count, querySelectorAll: () => cards };
vm.runInNewContext(source, { document: { querySelector: () => catalog } });
assert.equal(controls.hidden, false);
for (const button of buttons) {
 handler({ target: { closest: () => button } });
 const category = button.dataset.toolsFilter;
 const expected = roadmap.filter(t => category === 'all' || t.category_slug === category).length;
 assert.equal(cards.filter(c => !c.hidden).length, expected);
 assert.equal(count.textContent, `${expected} / 10 tools shown`);
 assert.equal(button.attrs['aria-pressed'], 'true');
 assert.equal(buttons.filter(b => b.attrs['aria-pressed'] === 'true').length, 1);
}
handler({ target: { closest: () => null } });
vm.runInNewContext(source, { document: { querySelector: () => null } });
console.log('PASS: all categories filter correctly, reset works, counts and aria-pressed stay consistent');
console.log('PASS: unrelated click and absent catalog are harmless; no browser/network dependencies');
