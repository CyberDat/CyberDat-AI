#!/bin/sh
set -eu
case "${1-}" in
 kev|nvd|cisa-advisories|cert-eu|msrc) action=sync ;;
 dispatch) action=dispatch ;;
 *) exit 64 ;;
esac
export HOME=/var/lib/cyberdat-staging
export WP_CLI_CONFIG_PATH=/var/lib/cyberdat-staging/cli.yml
if [ "$action" = sync ]; then
 set -- sync "--source=$1" --scheduled
else
 set -- dispatch
fi
exec /usr/bin/php8.4 -d memory_limit=192M -d disable_functions=mail -d sendmail_path=/bin/false -d opcache.enable_cli=0 -d sys_temp_dir=/var/lib/cyberdat-staging/tmp -d open_basedir=/var/www/cyberdat-staging:/var/lib/cyberdat-staging:/var/log/cyberdat-staging:/run/mysqld:/etc/ssl/certs:/opt/cyberdat-tools:/etc/cyberdat-staging /opt/cyberdat-tools/wp-cli.phar --path=/var/www/cyberdat-staging/public --no-color --skip-packages cyberdat-research "$@"
