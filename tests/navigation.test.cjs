'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const { runInNewContext } = require('node:vm');

const source = readFileSync(resolve(__dirname, '../wp-content/themes/cyberdat/assets/js/navigation.js'), 'utf8');
function fixture(isDesktop = false, missing = false) {
  const listeners = new Map();
  const document = { activeElement: null };
  const listen = (key, event, fn) => listeners.set(`${key}:${event}`, fn);
  function element(key) {
    return {
      hidden: key === 'toggle', attrs: {},
      addEventListener: (event, fn) => listen(key, event, fn),
      setAttribute(name, value) { this.attrs[name] = value; },
      contains(target) { return target === this || (key === 'nav' && target === link); },
      focus() { document.activeElement = this; },
    };
  }
  const toggle = element('toggle');
  const nav = element('nav');
  const link = { focus() { document.activeElement = this; }, closest: () => link };
  nav.querySelector = () => link;
  const media = { matches: isDesktop, addEventListener: (event, fn) => listen('media', event, fn) };
  document.querySelector = () => missing ? null : toggle;
  document.getElementById = () => missing ? null : nav;
  document.addEventListener = (event, fn) => listen('document', event, fn);
  runInNewContext(source, { document, window: { matchMedia: () => media } });
  return { toggle, nav, link, media, document,
    fire(key, event, payload = {}) { listeners.get(`${key}:${event}`)?.(payload); } };
}
test('mobile disclosure opens, updates ARIA, and Escape restores focus', () => {
  const f = fixture();
  assert.equal(f.toggle.hidden, false);
  assert.equal(f.nav.hidden, true);
  f.fire('toggle', 'click');
  assert.equal(f.toggle.attrs['aria-expanded'], 'true');
  assert.equal(f.nav.hidden, false);
  f.link.focus();
  let prevented = false;
  f.fire('document', 'keydown', { key: 'Escape', preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  assert.equal(f.toggle.attrs['aria-expanded'], 'false');
  assert.equal(f.nav.hidden, true);
  assert.equal(f.document.activeElement, f.toggle);
});
test('desktop navigation is visible and resizing does not hide keyboard focus', () => {
  const f = fixture(true);
  assert.equal(f.nav.hidden, false);
  assert.equal(f.toggle.hidden, true);
  f.link.focus();
  f.media.matches = false;
  f.fire('media', 'change');
  assert.equal(f.nav.hidden, true);
  assert.equal(f.document.activeElement, f.toggle);
  f.media.matches = true;
  f.fire('media', 'change');
  assert.equal(f.nav.hidden, false);
  assert.equal(f.document.activeElement, f.link);
});
test('outside click and moving focus out collapse mobile navigation', () => {
  const f = fixture();
  f.fire('toggle', 'click');
  f.fire('document', 'click', { target: {} });
  assert.equal(f.nav.hidden, true);
  f.fire('toggle', 'click');
  f.fire('document', 'focusin', { target: f.link });
  assert.equal(f.nav.hidden, false);
  f.fire('document', 'focusin', { target: {} });
  assert.equal(f.nav.hidden, true);
});
test('following a mobile navigation link closes the disclosure', () => {
  const f = fixture();
  f.fire('toggle', 'click');
  f.fire('nav', 'click', { target: f.link });
  assert.equal(f.nav.hidden, true);
});
test('pages without theme navigation do not throw', () => {
  assert.doesNotThrow(() => fixture(false, true));
});
