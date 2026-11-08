#!/usr/bin/env python3
"""Build browser-only fixtures; never reads production files or credentials."""
import json
from pathlib import Path

root = Path(__file__).resolve().parent
blueprint = {
    '$schema': 'https://playground.wordpress.net/blueprint-schema.json',
    'meta': {'title': 'CyberDat 0.4.0 + 3B — isolated theme inspection', 'author': 'CyberDat',
             'description': 'Premium editorial homepage with original local illustrations and a fictional offline threat dashboard, with browser-only demo content and 320/768/1440px checks. No production connection.'},
    'preferredVersions': {'php': '8.4', 'wp': '7.1.4'},
    'features': {'networking': False},
    'constants': {'CYBERDAT_PLAYGROUND': True, 'WP_ENVIRONMENT_TYPE': 'local',
                  'DISABLE_WP_CRON': True, 'DISALLOW_FILE_EDIT': True},
    'siteOptions': {'blogname': 'CyberDat', 'blog_public': '0',
                    'permalink_structure': '/%postname%/', 'category_base': 'topics'},
    'login': True,
    'landingPage': '/wp-content/cyberdat-preview/browser-checks.html',
    'steps': [
        {'step': 'installTheme', 'themeData': {
            'resource': 'git:directory', 'url': 'https://github.com/CyberDat/CyberDat-AI',
            'ref': '8536481ac9516e55a3910ef3f9b77dad96a98ab7', 'refType': 'commit',
            'path': 'wp-content/themes/cyberdat'},
         'options': {'activate': True, 'importStarterContent': False,
                     'targetFolderName': 'cyberdat', 'onError': 'throw'}},
        {'step': 'mkdir', 'path': '/wordpress/wp-content/mu-plugins'},
        {'step': 'writeFile', 'path': '/wordpress/wp-content/mu-plugins/cyberdat-preview-only.php',
         'data': (root / 'demo-support.php').read_text()},
        {'step': 'mkdir', 'path': '/wordpress/wp-content/cyberdat-preview'},
        {'step': 'writeFile', 'path': '/wordpress/wp-content/cyberdat-preview/browser-checks.html',
         'data': (root / 'browser-checks.html').read_text()},
        {'step': 'runPHP', 'code': (root / 'seed.php').read_text()},
        {'step': 'runPHP', 'code': (root / 'editorial-tests.php').read_text()},
        {'step': 'runPHP', 'code': (root / 'section-tests.php').read_text()},
    ],
}
(root / 'blueprint.json').write_text(json.dumps(blueprint, indent=2, ensure_ascii=False) + '\n')
print('Generated preview/blueprint.json')
