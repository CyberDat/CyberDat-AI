# CyberDat

Source repository for CyberDat.eu and future CyberDat SEO Intelligence integrations.

## WordPress theme foundation

The lightweight PHP/Gutenberg theme lives in `wp-content/themes/cyberdat/`.
See its README for scope, progressive navigation, integration ownership and preview requirements.

This repository does not include WordPress core, credentials, uploads or the production database.
Existing production MU plugins retain taxonomy, sitemap and Coming Soon responsibilities.

## Checks

With PHP 8.0+ and Node.js 18+ available:

```sh
find wp-content/themes/cyberdat -name '*.php' -exec php -l {} \;
node --check wp-content/themes/cyberdat/assets/js/navigation.js
node --test tests/navigation.test.cjs
```

Validate `theme.json` against its declared official WordPress schema. Navigation unit tests exercise disclosure state and focus behavior with lightweight DOM doubles; a real-browser accessibility and responsive review is still required.

## Release policy

Work is developed on feature branches. No automatic deployment is configured.
Production deployment, theme activation and removal of Coming Soon require separate approval.
The theme foundation has not been activated on production.
