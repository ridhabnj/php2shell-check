# php2shell-check

Read-only scanner that finds PHP installations affected by **php2shell**,
[CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and
[CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp):
two unauthenticated remote code execution flaws in PHP core (CVSS v4 9.2), fixed on 21 Oct 2026.
For each PHP build it finds, it says whether it is vulnerable and what to upgrade to.

Works on Debian/Ubuntu, RHEL/Alma/Rocky/CentOS, Alpine and macOS with plain POSIX `sh`.

## Run

```sh
curl -fsSL https://raw.githubusercontent.com/ridhabnj/php2shell-check/main/php2shell-check.sh | sudo sh
```

Without curl:

```sh
wget -qO- https://raw.githubusercontent.com/ridhabnj/php2shell-check/main/php2shell-check.sh | sudo sh
```

Run it as root for a complete scan (other users' processes, all containers). Without root it
still works, but may miss things.

Options go after `sh -s --`:

```sh
curl -fsSL .../php2shell-check.sh | sudo sh -s -- --deep --no-color
```

| Option | Effect |
|---|---|
| `--deep` | also search every local filesystem for PHP builds (slower) |
| `--no-containers` | skip running Docker/Podman containers |
| `--no-color` | plain output |

Piping a script from the internet into a root shell means trusting it. To review it first, or to
pin an exact version across a fleet, download it, read it, then run it:

```sh
curl -fsSLO https://raw.githubusercontent.com/ridhabnj/php2shell-check/<commit-sha>/php2shell-check.sh
less php2shell-check.sh
sudo sh php2shell-check.sh
```

### Many servers

Each run ends with a single machine-readable line:

```sh
for h in web1 web2 db1; do
  ssh "$h" 'curl -fsSL https://raw.githubusercontent.com/ridhabnj/php2shell-check/main/php2shell-check.sh | sudo sh -s -- --no-color' | grep '^RESULT'
done
# RESULT host=web1 vulnerable=1 patched=0 unknown=0 stale=0
```

Exit status: `0` nothing vulnerable, `1` vulnerable PHP or stale worker found, `2` only
undetermined builds.

## Example

An old official `php:8.2.20-apache` container where PHP was replaced on disk while Apache and a
PHP process kept running:

```
php2shell-check 1.0.0  CVE-2026-109618 + CVE-2026-109619 (PHP RCE, CVSS 9.2)
Host:   7235d2cd4d14 | Debian GNU/Linux 12 (bookworm), in a container | aarch64 | user root
Fixed:  8.2.35, 8.3.36, 8.4.27, 8.5.12 (8.1 and older: EOL, no upstream fix)

VULNERABLE  PHP 8.2.20
            /usr/local/bin/php  (cli)
            fix: update to PHP 8.2.35 or later
            official php Docker image: rebuild FROM php:8.2.35-<variant> and redeploy
RESTART     /usr/lib/apache2/modules/libphp.so (deleted on disk)
            still loaded by running processes, PIDs: 13
            restart the service (php-fpm, apache2/httpd, frankenphp) so it loads the updated build
RESTART     /usr/local/bin/php82old (deleted on disk)
            still running PHP 8.2.20, PIDs: 22
            restart the service (php-fpm, apache2/httpd, frankenphp) so it loads the updated build

Summary: 1 PHP installation(s): 1 vulnerable, 0 patched, 0 undetermined, 2 stale worker(s)
RESULT host=7235d2cd4d14 vulnerable=1 patched=0 unknown=0 stale=2
```

Ubuntu 22.04 with its patched PHP 8.1 package:

```
PATCHED     PHP 8.1.2-1ubuntu2.28
            /usr/bin/php8.1  (cli, php8.1-cli 8.1.2-1ubuntu2.28)
            /usr/sbin/php-fpm8.1  (fpm-fcgi, php8.1-fpm 8.1.2-1ubuntu2.28)
            vendor backport: CVE-2026-109618 and CVE-2026-109619 are in the package changelog
```

## What it checks

**Versions.** Fixed upstream releases are 8.2.35, 8.3.36, 8.4.27 and 8.5.12. PHP 8.1 and older are
end of life and get no upstream fix. For them the script suggests a vendor backport or a move to
8.3.36+ (8.2 itself goes EOL on 31 Dec 2026).

**Vendor backports.** Distros often patch an old version without changing its number (Ubuntu
22.04 ships the fix as `8.1.2-1ubuntu2.28`). For dpkg and rpm packages the script looks for both
CVE ids in the package changelog and reports the build as patched if they are there.

**Where it looks:**
- distro packages (`/usr/bin/php8.x`, `php-fpm`, `php-cgi`) and Apache modules (`libphp*.so`, `mod_php*.so`)
- Remi and Red Hat SCL, cPanel EasyApache, CloudLinux alt-php, Plesk, DirectAdmin, aaPanel,
  LiteSpeed `lsphp`, Bitnami, XAMPP, MAMP, Laravel Herd, Homebrew, phpenv, asdf, phpbrew, FrankenPHP
- running processes (Linux): PHP binaries and the `libphp` mapped into Apache workers
- running Docker and Podman containers, through `docker exec <id> php -v`
- with `--deep`, any PHP binary on local filesystems

**Stale workers.** Upgrading a package does not fix PHP-FPM or Apache processes that are already
running: they keep the old code in memory until restarted. On Linux the script reports processes
that still run, or still map, a PHP build that an upgrade deleted from disk.

**Exposure.** The advisories confirm RCE over HTTP against Apache mod_php with default settings, so
mod_php builds are flagged to patch first. PHP-FPM, CGI, LiteSpeed and FrankenPHP are affected too.

## Safety

The script only reads. It never installs, changes or restarts anything. Its temp files are removed
when it exits.

Run as root, it executes a binary (`php -v`) only when root owns it and nobody else can write to
it. Any other PHP build it finds, such as one in a user's home or one started by a user, is read
for its embedded version string and never executed. A planted fake `php` cannot become a root shell.

## Limits

- Stopped containers, images and Kubernetes pods are not scanned. Run the script inside the pod or
  container, or check the image's PHP version.
- Backports are detected for dpkg and rpm packages only. Alpine, Homebrew and self-built PHP are
  judged by their version number.
- A missing package changelog (minimal container images strip `/usr/share/doc`) means a backport
  cannot be verified. The script says so.
- PHP 8.6 pre-releases are reported as undetermined.
- Windows is not supported.

## Interim workarounds

Updating is the only complete fix. Until you can update, the advisories list partial measures, for
example `session.upload_progress.enabled=0` set administratively, followed by a restart of every
worker. Read the advisories before relying on any of them:

- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), CVE-2026-109618, RCE via OOM corruption
- [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp), CVE-2026-109619, RCE via stale global state

## Tests

`tests/run-matrix.sh` runs the script in Debian 12, Ubuntu 22.04, AlmaLinux 9, Alpine, official
`php` images (with stale workers and a planted user binary), FrankenPHP, and against containers seen
from the host. It needs Docker.

## License

[MIT](LICENSE)
