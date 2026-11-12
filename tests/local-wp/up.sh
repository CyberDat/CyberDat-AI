#!/usr/bin/env bash
# Start the disposable local WordPress used for Log Anonymizer acceptance.
# Usage: tests/local-wp/up.sh        (start + seed)
#        tests/local-wp/up.sh down   (stop and delete the disposable volumes)
set -euo pipefail
set +x
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")"
export LA_PORT="${LA_PORT:-8090}"
# Throwaway credential for a database that only holds generated test content.
export LA_DB_PASSWORD="${LA_DB_PASSWORD:-$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')}"

if [ "${1:-}" = "down" ]; then
	docker compose down -v --remove-orphans
	exit 0
fi

if docker volume inspect cyberdat-tools-dev-db >/dev/null 2>&1; then
	echo "Disposable volumes from a previous run exist. Run: tests/local-wp/up.sh down" >&2
	exit 3
fi
docker compose up -d --pull never
for i in $(seq 1 60); do
	if docker compose exec -T wordpress php -r 'exit(@mysqli_connect("db","wp_local",getenv("WORDPRESS_DB_PASSWORD"),"wp_local")?0:1);' >/dev/null 2>&1; then break; fi
	sleep 2
done
docker compose exec -T wordpress php /opt/cyberdat-seed/seed.php install
docker compose exec -T wordpress php /opt/cyberdat-seed/seed.php pages
echo "Local tool: http://127.0.0.1:${LA_PORT}/tools/log-anonymizer/"
echo "Local tool: http://127.0.0.1:${LA_PORT}/tools/prompt-injection-detector/"
