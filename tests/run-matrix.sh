#!/bin/sh
# Run php2shell-check.sh in throwaway containers of each supported distro.
# Usage: tests/run-matrix.sh [OUTDIR]   (needs Docker; outputs one file per case)

HERE=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT=$HERE/php2shell-check.sh
OUT=${1:-$HERE/tests/out}
mkdir -p "$OUT"

# run NAME IMAGE SETUP: install PHP with SETUP, then pipe the script into sh like `curl | sh`.
run() {
    docker run --rm -v "$SCRIPT:/check.sh:ro" "$2" sh -c "
        ( $3 ) >/tmp/setup.log 2>&1 || { echo SETUP FAILED; tail -n 30 /tmp/setup.log; exit 99; }
        cat /check.sh | sh -s -- --no-color; echo EXIT=\$?
        $4" >"$OUT/$1.txt" 2>&1
    echo "done: $1"
}

APT='export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq'

# Debian: mod_php loaded by a running Apache, plus a php-fpm whose binary was deleted
# while running (what a package upgrade without restart leaves behind).
run debian12 debian:12 "$APT php8.2-cli php8.2-fpm libapache2-mod-php8.2 &&
    cp /usr/sbin/php-fpm8.2 /usr/local/sbin/php-fpm-stale &&
    /usr/local/sbin/php-fpm-stale -D -y /etc/php/8.2/fpm/php-fpm.conf &&
    rm /usr/local/sbin/php-fpm-stale && apache2ctl start" \
    'echo "--- as nobody:"; su nobody -s /bin/sh -c "sh /check.sh --no-color"; echo EXIT=$?' &
run ubuntu2204 ubuntu:22.04 "$APT php8.1-cli php8.1-fpm" &
run alma9 almalinux:9 "dnf -y -q install php-cli php-fpm" &
run alpine alpine:3.20 "apk add --no-cache php83 php83-fpm php83-apache2" \
    'echo "--- deep:"; sh /check.sh --no-color --deep; echo EXIT=$?' &
run php82-apache php:8.2-apache "true" &
# Old official image with stale workers: a running Apache whose libphp.so is gone and a
# PHP built-in server whose binary is gone. Plus a user-owned "php-cgi" (really the CLI)
# that root must not execute: it must show up as (cgi-fcgi), not as (cli).
run stale php:8.2.20-apache "apache2ctl start && sleep 1 && rm /usr/lib/apache2/modules/libphp.so &&
    cp /usr/local/bin/php /usr/local/bin/php82old &&
    { /usr/local/bin/php82old -S 127.0.0.1:8080 >/dev/null 2>&1 & } && sleep 1 &&
    rm /usr/local/bin/php82old &&
    mkdir -p /home/evil/.phpenv/versions/9/bin && cp /usr/local/bin/php /home/evil/.phpenv/versions/9/bin/php-cgi &&
    chown -R nobody /home/evil" &
run frankenphp dunglas/frankenphp:latest "true" &
wait

# Containers seen from the host: one vulnerable EOL, one current, one without PHP.
docker run -d --rm --name p2s-php81 php:8.1-fpm-alpine >/dev/null
docker run -d --rm --name p2s-php84 php:8.4-cli sleep 300 >/dev/null
docker run -d --rm --name p2s-nophp alpine:3.20 sleep 300 >/dev/null
sh "$SCRIPT" --no-color >"$OUT/host-containers.txt" 2>&1
echo "EXIT=$?" >>"$OUT/host-containers.txt"
docker rm -f p2s-php81 p2s-php84 p2s-nophp >/dev/null
echo "done: host-containers"
