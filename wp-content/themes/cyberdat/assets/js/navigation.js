/* Progressive enhancement: navigation stays visible if JavaScript is unavailable. */
(() => {
	'use strict';
	const toggle = document.querySelector('[data-menu-toggle]');
	const navigation = document.getElementById('site-navigation');
	if (!toggle || !navigation) return;
	const desktop = window.matchMedia('(min-width: 64rem)');
	let expanded = false;

	const render = () => {
		toggle.hidden = desktop.matches;
		toggle.setAttribute('aria-expanded', String(!desktop.matches && expanded));
		navigation.hidden = !desktop.matches && !expanded;
	};
	const close = (restoreFocus = false) => {
		if (!expanded) return;
		expanded = false;
		render();
		if (restoreFocus && !desktop.matches) toggle.focus();
	};
	toggle.addEventListener('click', () => {
		expanded = !expanded;
		render();
	});
	document.addEventListener('keydown', (event) => {
		if (event.key === 'Escape' && expanded) {
			event.preventDefault();
			close(true);
		}
	});
	document.addEventListener('click', (event) => {
		if (!navigation.contains(event.target) && !toggle.contains(event.target)) close();
	});
	document.addEventListener('focusin', (event) => {
		if (!navigation.contains(event.target) && !toggle.contains(event.target)) close();
	});
	navigation.addEventListener('click', (event) => {
		if (!desktop.matches && event.target.closest('a')) close(true);
	});
	desktop.addEventListener('change', () => {
		// Do not leave keyboard focus inside a newly hidden mobile navigation.
		const focusInside = navigation.contains(document.activeElement);
		expanded = false;
		render();
		if (!desktop.matches && focusInside) toggle.focus();
		if (desktop.matches && document.activeElement === toggle) navigation.querySelector('a')?.focus();
	});
	render();
})();
