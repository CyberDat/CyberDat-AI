#!/usr/bin/env bash
# Threat map in a disposable WordPress: MariaDB + the pinned WordPress image + WP-CLI on an --internal Docker
# network (no internet). Checks migrate / status / sync / uninstall and tests/threat-map-wp-store.php.
#   bash tests/threat-map-wp-integration.sh <path-to-wp-cli.phar>
# Creates and removes its own containers and network (cdtm-it-*); touches nothing else.
set -euo pipefail
cd "$(dirname "$0")/.."
PHAR=${1:?wp-cli.phar path}
WP_IMAGE=wordpress@sha256:bb954f75881438923ce702aa48d360a2a45f66ff3b4a1e45aac4876d5c007676
DB_IMAGE=mariadb@sha256:78a5047d3ba33975f183f183c2464cc7f1eab13ec8667e57cc9a5821d6da7577
NET=cdtm-it-net; DB=cdtm-it-db
PW=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')
cleanup() { docker rm -f "$DB" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker network create --internal "$NET" >/dev/null
docker run -d --name "$DB" --network "$NET" -e MARIADB_ROOT_PASSWORD="$PW" -e MARIADB_DATABASE=wp -e MARIADB_USER=wp -e MARIADB_PASSWORD="$PW" "$DB_IMAGE" >/dev/null
root=$(pwd -W 2>/dev/null || pwd)
phar_dir=$(cd "$(dirname "$PHAR")" && (pwd -W 2>/dev/null || pwd))
MSYS_NO_PATHCONV=1 docker run --rm --network "$NET" -e PW="$PW" \
	-v "$root/wp-content/themes/cyberdat":/theme:ro -v "$root/tests":/tests:ro -v "$root/tests/fixtures/threat-map":/fixtures:ro -v "$phar_dir":/wpcli:ro \
	-e PAGER=cat --entrypoint bash "$WP_IMAGE" -c '
set -u
mkdir -p /tmp/wp && cp -a /usr/src/wordpress/. /tmp/wp/ && ln -s /theme /tmp/wp/wp-content/themes/cyberdat && cd /tmp/wp
wp() { php -d memory_limit=512M /wpcli/'"$(basename "$PHAR")"' --allow-root --path=/tmp/wp "$@"; }
for i in $(seq 1 60); do php -r "exit(@mysqli_connect(\"cdtm-it-db\",\"wp\",getenv(\"PW\"),\"wp\")?0:1);" 2>/dev/null && break; sleep 1; done
wp config create --dbname=wp --dbuser=wp --dbpass="$PW" --dbhost=cdtm-it-db --skip-check --quiet
wp core install --url=http://localhost --title=IT --admin_user=it --admin_password="$PW" --admin_email=it@example.invalid --skip-email --quiet
wp theme activate cyberdat --quiet
echo "== help"; wp help cyberdat threatmap | sed -n "1,20p"
echo "== status before migrate (expected error)"; wp cyberdat threatmap status 2>&1 || echo "exit $?"
echo "== migrate"; wp cyberdat threatmap migrate
echo "== store checks"; CDTM_FIXTURE=/fixtures/feodo-ipblocklist.json wp eval-file /tests/threat-map-wp-store.php
echo "== sync --force without internet (expected: feodo network error, ransomware not configured)"; wp cyberdat threatmap sync --force 2>&1 || echo "exit $?"
echo "== sync --force again at once (expected: MIN_INTERVAL)"; wp cyberdat threatmap sync --force 2>&1 || echo "exit $?"
echo "== sync --layer=nope"; wp cyberdat threatmap sync --layer=nope 2>&1 || echo "exit $?"
echo "== status"; wp cyberdat threatmap status
wp cyberdat threatmap status --format=json > /tmp/status.json && php -r "\$s=json_decode(file_get_contents(\"/tmp/status.json\"),true);foreach(\$s as \$r){echo \$r[\"layer\"],\": \",\$r[\"freshness\"],\" / \",\$r[\"last_run\"],\" / \",\$r[\"error\"],PHP_EOL;}"
echo "== uninstall without --yes (expected error)"; wp cyberdat threatmap uninstall 2>&1 || echo "exit $?"
echo "== uninstall --yes"; wp cyberdat threatmap uninstall --yes
wp eval "global \$wpdb; echo \"tables left: \", count(\$wpdb->get_col(\"SHOW TABLES LIKE \x27{\$wpdb->prefix}cdtm_%\x27\")), PHP_EOL;"
'
