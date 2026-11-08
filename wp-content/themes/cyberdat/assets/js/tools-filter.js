/* Progressive enhancement: all roadmap cards are server-rendered without JS. */
(() => {
  'use strict';
  const catalog = document.querySelector('[data-tools-catalog]');
  if (!catalog) return;
  const controls = catalog.querySelector('[data-tools-filters]');
  const count = catalog.querySelector('[data-tools-count]');
  const cards = Array.from(catalog.querySelectorAll('[data-tool-category]'));
  if (!controls || !count || !cards.length) return;
  const buttons = Array.from(controls.querySelectorAll('[data-tools-filter]'));
  controls.hidden = false;
  controls.addEventListener('click', (event) => {
    const button = event.target.closest('[data-tools-filter]');
    if (!button || !controls.contains(button)) return;
    const category = button.dataset.toolsFilter;
    buttons.forEach((item) => item.setAttribute('aria-pressed', String(item === button)));
    let visible = 0;
    cards.forEach((card) => {
      card.hidden = category !== 'all' && card.dataset.toolCategory !== category;
      if (!card.hidden) visible += 1;
    });
    count.textContent = `${visible} / ${cards.length} ${count.dataset.countLabel}`;
  });
})();
