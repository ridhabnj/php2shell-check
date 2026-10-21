#!/bin/sh
# php2shell-check: find PHP installations affected by "php2shell"
# (CVE-2026-109618 / CVE-2026-109619) and say which release fixes each one.
#
#   curl -fsSL https://raw.githubusercontent.com/ridhabnj/php2shell-check/main/php2shell-check.sh | sudo sh
#
# Read-only: it runs `php -v`, queries the package database and reads /proc.
# It never installs, modifies or restarts anything.
#
# Plain POSIX sh (dash, busybox ash, bash): Debian/Ubuntu, RHEL family, Alpine,
# macOS. Everything runs from main() at the bottom, so a truncated download
# never executes half a script.

SCRIPT_VERSION=1.0.0
CVE_A=CVE-2026-109618
CVE_B=CVE-2026-109619
# Upstream releases that fix both CVEs (php.net, 21 Oct 2026). Older branches are EOL.
FIXED_RELEASES="8.2.35 8.3.36 8.4.27 8.5.12"
# Migration target suggested for EOL branches (8.2 itself goes EOL on 31 Dec 2026).
MIGRATE_TARGET=8.3.36
ADVISORY_A=https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
ADVISORY_B=https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp

TAB=$(printf '\t')
# Field separator of the results file: not IFS whitespace, so empty fields survive `read`.
US=$(printf '\037')

usage() {
    cat <<EOF
php2shell-check $SCRIPT_VERSION: find PHP affected by $CVE_A / $CVE_B

Usage:
  sh php2shell-check.sh [options]
  curl -fsSL <raw-url>/php2shell-check.sh | sudo sh -s -- [options]

Options:
  --deep           also search every local filesystem for PHP builds (slow)
  --no-containers  do not look inside running Docker/Podman containers
  --no-color       disable colors
  -h, --help       show this help
  -V, --version    show the script version

Exit status: 0 nothing vulnerable, 1 vulnerable PHP or stale worker found,
2 only undetermined builds, 64 usage error.
EOF
}

setup_colors() {
    RED='' GRN='' YEL='' BLD='' DIM='' RST=''
    if [ "$USE_COLOR" = 1 ] && [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
        RED=$(printf '\033[31m') GRN=$(printf '\033[32m') YEL=$(printf '\033[33m')
        BLD=$(printf '\033[1m') DIM=$(printf '\033[2m') RST=$(printf '\033[0m')
    fi
}

# ver_ge A B: true when version A >= B, comparing the first three numeric fields.
ver_ge() {
    awk -v a="$1" -v b="$2" 'BEGIN {
        split(a, x, "."); split(b, y, ".")
        for (i = 1; i <= 3; i++) {
            if (x[i] + 0 > y[i] + 0) exit 0
            if (x[i] + 0 < y[i] + 0) exit 1
        }
        exit 0
    }'
}

# fixed_for BRANCH: print the upstream release fixing BRANCH (e.g. 8.3 -> 8.3.36).
fixed_for() {
    for _ff in $FIXED_RELEASES; do
        if [ "${_ff%.*}" = "$1" ]; then
            echo "$_ff"
            return 0
        fi
    done
    return 1
}

# resolve PATH: follow symlinks without readlink -f (missing on older macOS).
resolve() {
    _rs_p=$1 _rs_n=0
    while [ -L "$_rs_p" ] && [ "$_rs_n" -lt 40 ]; do
        _rs_l=$(readlink "$_rs_p") || break
        case $_rs_l in
            /*) _rs_p=$_rs_l ;;
            *) _rs_p=${_rs_p%/*}/$_rs_l ;;
        esac
        _rs_n=$((_rs_n + 1))
    done
    _rs_d=$(cd -P "${_rs_p%/*}/" 2>/dev/null && pwd -P) && _rs_p=${_rs_d%/}/${_rs_p##*/}
    printf '%s\n' "$_rs_p"
}

# php_name NAME: true when a file name looks like a PHP SAPI binary.
php_name() {
    case $1 in
        *config* | *ize* | *.so | *.ini | *.conf | *.sh | *.bak | *.old | *.dist) return 1 ;;
        php | php[0-9]* | php-fpm* | php-cgi* | lsphp*) return 0 ;;
    esac
    return 1
}

# add_cand KIND PATH: queue a file for checking, once per real path.
# KIND is bin (php, php-fpm, php-cgi, lsphp), frankenphp or mod (Apache libphp.so).
add_cand() {
    [ -f "$2" ] || return 0
    case $1 in bin | frankenphp) [ -x "$2" ] || return 0 ;; esac
    _ac_real=$(resolve "$2")
    grep -Fxq -- "$_ac_real" "$TMP/seen" 2>/dev/null && return 0
    printf '%s\n' "$_ac_real" >>"$TMP/seen"
    # Wrapper scripts (Remi's /usr/bin/php82, shims): the real binary is found elsewhere.
    [ "$(dd if="$_ac_real" bs=2 count=1 2>/dev/null)" = '#!' ] && return 0
    printf '%s\t%s\t%s\n' "$1" "$_ac_real" "$2" >>"$TMP/cands"
}

collect_static() {
    for _cs_f in \
        /usr/bin/php* /usr/sbin/php* /usr/local/bin/php* /usr/local/sbin/php* \
        /bin/php* /sbin/php* /usr/lib/cgi-bin/php* \
        /opt/remi/php*/root/usr/bin/php* /opt/remi/php*/root/usr/sbin/php-fpm \
        /opt/rh/rh-php*/root/usr/bin/php* /opt/rh/rh-php*/root/usr/sbin/php-fpm \
        /opt/cpanel/ea-php*/root/usr/bin/php* /opt/cpanel/ea-php*/root/usr/sbin/php-fpm \
        /opt/alt/php*/usr/bin/php* /opt/alt/php*/usr/sbin/php-fpm \
        /opt/plesk/php/*/bin/php* /opt/plesk/php/*/sbin/php-fpm \
        /usr/local/php*/bin/php* /usr/local/php*/sbin/php-fpm \
        /usr/local/lsws/lsphp*/bin/php* /usr/local/lsws/lsphp*/bin/lsphp \
        /opt/bitnami/php/bin/php* /opt/bitnami/php/sbin/php-fpm \
        /opt/php*/bin/php* /opt/php*/sbin/php-fpm \
        /www/server/php/*/bin/php* /www/server/php/*/sbin/php-fpm \
        /opt/lampp/bin/php* /Applications/XAMPP/xamppfiles/bin/php* \
        /Applications/MAMP/bin/php/php*/bin/php* \
        /opt/homebrew/opt/php*/bin/php* /opt/homebrew/opt/php*/sbin/php-fpm \
        /usr/local/opt/php*/bin/php* /usr/local/opt/php*/sbin/php-fpm \
        /root/.phpenv/versions/*/bin/php* /home/*/.phpenv/versions/*/bin/php* \
        /Users/*/.phpenv/versions/*/bin/php* \
        /root/.asdf/installs/php/*/bin/php* /home/*/.asdf/installs/php/*/bin/php* \
        /Users/*/.asdf/installs/php/*/bin/php* \
        /root/.phpbrew/php/*/bin/php* /home/*/.phpbrew/php/*/bin/php* \
        /Users/*/.phpbrew/php/*/bin/php* \
        /Users/*/Library/"Application Support"/Herd/bin/php*; do
        php_name "${_cs_f##*/}" && add_cand bin "$_cs_f"
    done
    for _cs_f in /usr/bin/frankenphp /usr/local/bin/frankenphp /opt/homebrew/bin/frankenphp; do
        add_cand frankenphp "$_cs_f"
    done
    for _cs_f in \
        /usr/lib/apache2/modules/libphp*.so /usr/lib/apache2/mod_php*.so \
        /usr/lib64/httpd/modules/libphp*.so /usr/lib/httpd/modules/libphp*.so \
        /usr/local/apache2/modules/libphp*.so /usr/local/apache/modules/libphp*.so \
        /opt/homebrew/opt/php*/lib/httpd/modules/libphp*.so \
        /usr/local/opt/php*/lib/httpd/modules/libphp*.so; do
        add_cand mod "$_cs_f"
    done
    for _cs_f in php php-fpm php-cgi; do
        _cs_p=$(command -v "$_cs_f" 2>/dev/null) && add_cand bin "$_cs_p"
    done
    _cs_p=$(command -v frankenphp 2>/dev/null) && add_cand frankenphp "$_cs_p"
}

# Linux only: PHP binaries and Apache modules of running processes, plus workers
# still running a binary that an upgrade already deleted (they need a restart).
collect_processes() {
    [ -e /proc/self/exe ] || return 0
    _cp_self=$(readlink /proc/self/ns/mnt 2>/dev/null)
    # shellcheck disable=SC2012 # one ls beats a readlink fork per process
    ls -l /proc/[0-9]*/exe 2>/dev/null |
        sed -n 's#^.* /proc/\([0-9][0-9]*\)/exe -> \(.*\)$#\1 \2#p' >"$TMP/procs"
    while read -r _cp_pid _cp_exe; do
        _cp_bin=${_cp_exe% (deleted)}
        _cp_name=${_cp_bin##*/}
        case $_cp_name in
            frankenphp) _cp_kind=frankenphp ;;
            apache | apache2 | httpd | httpd.* | httpd-*) _cp_kind=web ;;
            *) if php_name "$_cp_name"; then _cp_kind=bin; else continue; fi ;;
        esac
        # Processes of other mount namespaces live in containers: scanned with `docker exec`.
        _cp_ns=$(readlink "/proc/$_cp_pid/ns/mnt" 2>/dev/null)
        [ -n "$_cp_self" ] && [ -n "$_cp_ns" ] && [ "$_cp_ns" != "$_cp_self" ] && continue
        if [ "$_cp_kind" = web ]; then
            _cp_so=$(grep -E 'libphp|mod_php' "/proc/$_cp_pid/maps" 2>/dev/null | head -n 1 | sed 's#^[^/]*##')
            [ -n "$_cp_so" ] || continue
            _cp_bin=${_cp_so% (deleted)} _cp_exe=$_cp_so _cp_kind=mod
        fi
        case $_cp_exe in
            *" (deleted)") printf '%s\t%s\t%s\n' "$_cp_bin" "$_cp_pid" "$_cp_kind" >>"$TMP/stale" ;;
            *) add_cand "$_cp_kind" "$_cp_bin" ;;
        esac
    done <"$TMP/procs"
}

collect_deep() {
    find / \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap \
        -o -path /var/lib/docker -o -path /var/lib/containerd -o -path /var/lib/containers \
        -o -path /System -o -path /Volumes -o -path /private/var/folders \) -prune -o \
        -type f \( \( -perm -100 \( -name 'php*' -o -name 'lsphp*' -o -name frankenphp \) \) \
        -o -name 'libphp*.so' -o -name 'mod_php*.so' \) -print 2>/dev/null >"$TMP/deep"
    while IFS='' read -r _cd_f; do
        case ${_cd_f##*/} in
            frankenphp) add_cand frankenphp "$_cd_f" ;;
            libphp*.so | mod_php*.so) add_cand mod "$_cd_f" ;;
            *) php_name "${_cd_f##*/}" && add_cand bin "$_cd_f" ;;
        esac
    done <"$TMP/deep"
}

# php_line KIND: keep the "PHP <version> (<sapi>)" line of `php -v` / `frankenphp version`.
php_line() {
    if [ "$1" = frankenphp ]; then
        sed -n 's/.*\(PHP [0-9][^ ]*\).*/\1 (frankenphp)/p' | head -n 1
    else
        sed -n '/^PHP [0-9]/p' | head -n 1
    fi
}

# file_version FILE: version baked into a PHP build ("X-Powered-By: PHP/<version>"),
# for files that cannot be executed (Apache modules, foreign arch, deleted binaries).
file_version() {
    _fv=$(LC_ALL=C grep -a -o -m 1 'X-Powered-By: PHP/[0-9][0-9A-Za-z.+~_-]*' "$1" 2>/dev/null)
    if [ $? -gt 1 ]; then # grep without -a/-o/-m: slower but portable
        _fv=$(LC_ALL=C tr -c '[:print:]' '\n' <"$1" 2>/dev/null | grep 'X-Powered-By: PHP/[0-9]')
    fi
    printf '%s\n' "$_fv" | sed -n 's#^.*X-Powered-By: PHP/\([0-9][^ ]*\).*$#\1#p' | head -n 1
}

# safe_to_exec FILE: as root, only run binaries owned by root and not writable by
# group/others. Anything else (a "php" planted in /home, /tmp or a process) is read,
# never executed, so this script cannot be turned into a root shell.
safe_to_exec() {
    [ "$IS_ROOT" = 1 ] || return 0
    _se=$(ls -lnd "$1" 2>/dev/null) || return 1
    # shellcheck disable=SC2086 # split the ls fields
    set -- $_se
    case $1 in ?????w* | ????????w*) return 1 ;; esac
    [ "$3" = 0 ]
}

# read_version KIND PATH: sets V_FULL (e.g. 8.1.2-1ubuntu2.20) and V_SAPI.
read_version() {
    V_FULL='' V_SAPI='' _rv_line=''
    if safe_to_exec "$2"; then
        case $1 in
            bin) _rv_line=$("$2" -v </dev/null 2>/dev/null | php_line bin) ;;
            frankenphp) _rv_line=$("$2" version </dev/null 2>/dev/null | php_line frankenphp) ;;
        esac
    fi
    if [ -n "$_rv_line" ]; then
        V_FULL=$(printf '%s\n' "$_rv_line" | sed 's/^PHP \([^ ]*\).*/\1/')
        V_SAPI=$(printf '%s\n' "$_rv_line" | sed -n 's/^PHP [^ ]* (\([^)]*\)).*/\1/p')
    else
        V_FULL=$(file_version "$2")
    fi
    if [ -z "$V_SAPI" ]; then
        case $1:${2##*/} in
            mod:*) V_SAPI=apache2handler ;;
            frankenphp:*) V_SAPI=frankenphp ;;
            *:*fpm*) V_SAPI=fpm-fcgi ;;
            *:*cgi*) V_SAPI=cgi-fcgi ;;
            *:lsphp*) V_SAPI=litespeed ;;
            *) V_SAPI=cli ;;
        esac
    fi
}

# pkg_owner PATH...: sets PKG_MGR, PKG_NAME, PKG_VER for the package owning the file.
pkg_owner() {
    PKG_MGR='' PKG_NAME='' PKG_VER=''
    for _po_p in "$@"; do
        case $_po_p in
            */Cellar/*/*/*)
                PKG_MGR=brew
                PKG_NAME=$(printf '%s\n' "$_po_p" | sed 's#^.*/Cellar/\([^/]*\)/.*#\1#')
                PKG_VER=$(printf '%s\n' "$_po_p" | sed 's#^.*/Cellar/[^/]*/\([^/]*\)/.*#\1#')
                return 0
                ;;
        esac
        if command -v dpkg-query >/dev/null 2>&1; then
            _po_o=$(dpkg-query -S "$_po_p" 2>/dev/null | head -n 1)
            if [ -n "$_po_o" ]; then
                PKG_NAME=${_po_o%%:*} PKG_MGR=dpkg
                PKG_NAME=${PKG_NAME%%,*}
                PKG_VER=$(dpkg-query -W -f='${Version}' "$PKG_NAME" 2>/dev/null)
                return 0
            fi
        fi
        if command -v rpm >/dev/null 2>&1; then
            _po_o=$(rpm -qf --qf '%{NAME} %{VERSION}-%{RELEASE}\n' "$_po_p" 2>/dev/null | head -n 1)
            case $_po_o in
                "" | *" not owned "* | *"No such"*) ;;
                *) PKG_MGR=rpm PKG_NAME=${_po_o%% *} PKG_VER=${_po_o#* }; return 0 ;;
            esac
        fi
        if command -v apk >/dev/null 2>&1; then
            _po_o=$(apk info -W "$_po_p" 2>/dev/null | sed -n 's/^.* is owned by //p' | head -n 1)
            if [ -n "$_po_o" ]; then
                PKG_MGR=apk PKG_NAME=${_po_o%-*-*}
                PKG_VER=${_po_o#"$PKG_NAME"-}
                return 0
            fi
        fi
    done
    return 1
}

# backport_hits BRANCH: how many of the two CVE ids the owning package's changelog
# mentions (distros patch old versions without bumping the upstream number).
# Prints "none" when no changelog is available to look at.
backport_hits() {
    : >"$TMP/changelog"
    case $PKG_MGR in
        dpkg)
            for _bh_d in "$PKG_NAME" "${PKG_NAME%-*}-common" "php$1-common"; do
                _bh_f=/usr/share/doc/$_bh_d/changelog.Debian.gz
                if [ -r "$_bh_f" ]; then
                    gzip -dc "$_bh_f" >"$TMP/changelog" 2>/dev/null
                    break
                fi
            done
            ;;
        rpm) rpm -q --changelog "$PKG_NAME" >"$TMP/changelog" 2>/dev/null ;;
    esac
    if [ ! -s "$TMP/changelog" ]; then
        echo none
        return
    fi
    _bh_n=0
    grep -q "$CVE_A" "$TMP/changelog" && _bh_n=$((_bh_n + 1))
    grep -q "$CVE_B" "$TMP/changelog" && _bh_n=$((_bh_n + 1))
    echo "$_bh_n"
}

# assess VERSION: sets ST (VULNERABLE, PATCHED or UNKNOWN), BRANCH, TARGET, EOL, WHY.
assess() {
    ST=UNKNOWN BRANCH='' TARGET='' EOL=0 WHY=''
    _as_up=$(printf '%s\n' "$1" | sed -n 's/^\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
    if [ -z "$_as_up" ]; then
        WHY="cannot parse version '$1'"
        return
    fi
    BRANCH=${_as_up%.*}
    if TARGET=$(fixed_for "$BRANCH"); then
        if ver_ge "$_as_up" "$TARGET"; then ST=PATCHED; else ST=VULNERABLE; fi
    elif ver_ge "$_as_up" "${FIXED_RELEASES##* }"; then
        WHY="branch $BRANCH is a pre-release not covered by the advisory: use ${FIXED_RELEASES##* } in production"
    else
        ST=VULNERABLE EOL=1 TARGET=$MIGRATE_TARGET
    fi
}

# remediation: what a VULNERABLE result needs, from BRANCH, TARGET and EOL.
remediation() {
    if [ "$EOL" = 1 ]; then
        echo "PHP $BRANCH is EOL: no upstream fix. Use a vendor backport if one exists, or migrate to PHP $MIGRATE_TARGET+"
    else
        echo "fix: update to PHP $TARGET or later"
    fi
}

# update_cmd MGR PATH PKG...: the command (or advice) that gets a fixed build
# for one installation, given the packages owning its binaries.
update_cmd() {
    _uc_mgr=$1 _uc_path=$2 _uc_args=''
    shift 2
    for _uc_n in "$@"; do
        case $_uc_mgr:$_uc_n in
            brew:*) _uc_t=$_uc_n ;;
            dpkg:libapache2-mod-php*) _uc_t="'$_uc_n'" ;;
            *) _uc_t="'${_uc_n%-*}*'" ;;
        esac
        case " $_uc_args " in *" $_uc_t "*) ;; *) _uc_args="$_uc_args $_uc_t" ;; esac
    done
    case $_uc_mgr in
        dpkg) echo "\$ apt-get update && apt-get install --only-upgrade$_uc_args" ;;
        rpm)
            _uc_dnf=dnf
            command -v dnf >/dev/null 2>&1 || _uc_dnf=yum
            echo "\$ $_uc_dnf upgrade$_uc_args"
            ;;
        apk) echo "\$ apk update && apk upgrade" ;;
        brew) echo "\$ brew update && brew upgrade$_uc_args" ;;
        container) echo "rebuild the image on a fixed PHP (e.g. FROM php:$TARGET-<variant>) and redeploy" ;;
        *)
            case $_uc_path in
                */Herd/*) echo "update PHP from Laravel Herd" ;;
                /Applications/MAMP/*) echo "update MAMP" ;;
                /usr/local/*)
                    if [ -f /usr/local/bin/docker-php-source ]; then
                        echo "official php Docker image: rebuild FROM php:$TARGET-<variant> and redeploy"
                    else
                        echo "built from source: rebuild from php-$TARGET"
                    fi
                    ;;
                *) echo "not managed by a package manager: reinstall it from a fixed release" ;;
            esac
            ;;
    esac
}

# show STATUS LABEL [DETAIL...]
show() {
    case $1 in
        VULNERABLE | RESTART) _sh_c=$RED ;;
        PATCHED) _sh_c=$GRN ;;
        *) _sh_c=$YEL ;;
    esac
    printf '%s%-10s%s  %s\n' "$_sh_c$BLD" "$1" "$RST" "$2"
    shift 2
    for _sh_l in "$@"; do
        [ -n "$_sh_l" ] && printf '            %s\n' "$_sh_l"
    done
    return 0
}

count() {
    case $1 in
        VULNERABLE) N_VULN=$((N_VULN + 1)) ;;
        PATCHED) N_OK=$((N_OK + 1)) ;;
        *) N_UNK=$((N_UNK + 1)) ;;
    esac
}

# record GROUP LABEL MGR PKG PKGVER NOTE: store one checked binary. Binaries
# with the same GROUP are reported together as one installation.
record() {
    printf '%s\n' "$1$US$ST$US$V_FULL$US$2$US$V_SAPI$US$3$US$4$US$5$US$6$US$WHY$US$BRANCH$US$TARGET$US$EOL" \
        >>"$TMP/results"
}

check_install() { # KIND REALPATH ORIGPATH
    read_version "$1" "$2"
    [ -n "$V_FULL" ] || return 0 # not a PHP build after all
    pkg_owner "$2" "$3"
    assess "$V_FULL"
    if [ "$ST" = VULNERABLE ]; then
        case $(backport_hits "$BRANCH") in
            2) ST=PATCHED WHY="vendor backport: $CVE_A and $CVE_B are in the package changelog" ;;
            1) WHY="only one of the two CVEs is in the package changelog" ;;
            none) [ "$PKG_MGR" = dpkg ] && WHY="package changelog not installed: a vendor backport cannot be verified" ;;
        esac
    fi
    _ci_note=''
    [ "$ST" = VULNERABLE ] && [ "$V_SAPI" = apache2handler ] &&
        _ci_note="mod_php: most exposed setup (RCE confirmed over HTTP), patch first"
    record "$ST|$V_FULL|$PKG_MGR|$WHY" "$2" "$PKG_MGR" "$PKG_NAME" "$PKG_VER" "$_ci_note"
}

print_results() {
    [ -s "$TMP/results" ] || return 0
    awk -F "$US" '!seen[$1]++ { print $1 }' "$TMP/results" >"$TMP/keys"
    while IFS='' read -r _pr_key; do
        awk -F "$US" -v k="$_pr_key" '$1 == k' "$TMP/results" >"$TMP/group"
        IFS=$US read -r _ ST V_FULL _pr_path _ _pr_mgr _ _ _ WHY BRANCH TARGET EOL <"$TMP/group"
        count "$ST"
        show "$ST" "${BLD}PHP $V_FULL${RST}"
        while IFS=$US read -r _ _ _ _pr_label _pr_sapi _ _pr_pkg _pr_pver _pr_note _; do
            printf '            %s  %s(%s%s)%s%s\n' "$_pr_label" "$DIM" "$_pr_sapi" \
                "${_pr_pkg:+, $_pr_pkg $_pr_pver}" "$RST" "${_pr_note:+  $YEL$_pr_note$RST}"
        done <"$TMP/group"
        [ -n "$WHY" ] && printf '            %s\n' "$WHY"
        if [ "$ST" = VULNERABLE ]; then
            printf '            %s\n' "$(remediation)"
            # shellcheck disable=SC2046 # one argument per package name
            printf '            %s%s%s\n' "$BLD" \
                "$(update_cmd "$_pr_mgr" "$_pr_path" $(awk -F "$US" '{ print $7 }' "$TMP/group" | sort -u))" "$RST"
        fi
    done <"$TMP/keys"
}

# report_stale: processes still running a PHP build deleted by an upgrade.
report_stale() {
    [ -s "$TMP/stale" ] || return 0
    cut -f1 "$TMP/stale" | sort -u >"$TMP/stale_paths"
    while IFS='' read -r _st_path; do
        _st_pids=$(awk -F "$TAB" -v p="$_st_path" '$1 == p { print $2 }' "$TMP/stale" | tr '\n' ' ' | sed 's/ $//')
        _st_kind=$(awk -F "$TAB" -v p="$_st_path" '$1 == p { print $3; exit }' "$TMP/stale")
        _st_v=''
        [ "$_st_kind" != mod ] && _st_v=$(file_version "/proc/${_st_pids%% *}/exe")
        if [ -n "$_st_v" ]; then
            assess "$_st_v"
            [ "$ST" = PATCHED ] && continue
            _st_what="still running PHP $_st_v"
        else
            _st_what="still loaded by running processes"
        fi
        N_STALE=$((N_STALE + 1))
        show RESTART "$_st_path (deleted on disk)" "$_st_what, PIDs: $_st_pids" \
            "restart the service (php-fpm, apache2/httpd, frankenphp) so it loads the updated build"
    done <"$TMP/stale_paths"
}

scan_containers() {
    [ "$SCAN_CONTAINERS" = 1 ] || return 0
    for _sc_rt in docker podman; do
        command -v "$_sc_rt" >/dev/null 2>&1 || continue
        if ! "$_sc_rt" ps -q </dev/null >"$TMP/ctr" 2>/dev/null; then
            CTR_NOTE="$CTR_NOTE $_sc_rt (not accessible, run as root)"
            continue
        fi
        CTR_NOTE="$CTR_NOTE $_sc_rt ($(wc -l <"$TMP/ctr" | tr -d ' ') running)"
        while read -r _sc_id; do
            [ -n "$_sc_id" ] || continue
            _sc_line=''
            for _sc_try in "php -v" "php-fpm -v" "frankenphp version"; do
                _sc_kind=bin
                [ "$_sc_try" = "frankenphp version" ] && _sc_kind=frankenphp
                # shellcheck disable=SC2086 # $_sc_try is a command and its argument
                _sc_line=$("$_sc_rt" exec "$_sc_id" $_sc_try </dev/null 2>/dev/null | php_line "$_sc_kind")
                [ -n "$_sc_line" ] && break
            done
            [ -n "$_sc_line" ] || continue
            _sc_name=$("$_sc_rt" inspect -f '{{.Name}}' "$_sc_id" </dev/null 2>/dev/null)
            _sc_img=$("$_sc_rt" inspect -f '{{.Config.Image}}' "$_sc_id" </dev/null 2>/dev/null)
            V_FULL=$(printf '%s\n' "$_sc_line" | sed 's/^PHP \([^ ]*\).*/\1/')
            V_SAPI=$(printf '%s\n' "$_sc_line" | sed -n 's/^PHP [^ ]* (\([^)]*\)).*/\1/p')
            assess "$V_FULL"
            _sc_note=''
            if [ "$ST" = VULNERABLE ]; then
                case $V_FULL in
                    *-* | *+*) _sc_note="distro PHP package: run this script inside the container to check for a vendor backport" ;;
                esac
            fi
            record "ctr|$_sc_rt|$_sc_id" "$_sc_rt:${_sc_name#/} [$_sc_img]" container "" "" "$_sc_note"
        done <"$TMP/ctr"
    done
}

detect_os() {
    OS_NAME=$(uname -s)
    case $OS_NAME in
        Darwin) OS_NAME="macOS $(sw_vers -productVersion 2>/dev/null)" ;;
        Linux)
            if [ -r /etc/os-release ]; then
                # shellcheck source=/dev/null
                OS_NAME=$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-${NAME:-Linux}}")
            elif [ -r /etc/redhat-release ]; then
                OS_NAME=$(cat /etc/redhat-release)
            fi
            if [ -f /.dockerenv ] || [ -f /run/.containerenv ]; then
                OS_NAME="$OS_NAME, in a container"
            fi
            ;;
    esac
}

main() {
    DEEP=0 SCAN_CONTAINERS=1 USE_COLOR=1
    while [ $# -gt 0 ]; do
        case $1 in
            --deep) DEEP=1 ;;
            --no-containers | --no-docker) SCAN_CONTAINERS=0 ;;
            --no-color) USE_COLOR=0 ;;
            -h | --help) usage; exit 0 ;;
            -V | --version) echo "php2shell-check $SCRIPT_VERSION"; exit 0 ;;
            *) echo "php2shell-check: unknown option: $1" >&2; usage >&2; exit 64 ;;
        esac
        shift
    done
    setup_colors

    TMP=$(mktemp -d 2>/dev/null || mktemp -d -t php2shell) || {
        echo "php2shell-check: cannot create a temporary directory" >&2
        exit 70
    }
    trap 'rm -rf "$TMP"' EXIT
    trap 'exit 130' INT TERM
    : >"$TMP/seen"
    : >"$TMP/cands"
    : >"$TMP/stale"
    : >"$TMP/results"
    N_VULN=0 N_OK=0 N_UNK=0 N_STALE=0 CTR_NOTE=''

    IS_ROOT=0
    [ "$(id -u)" = 0 ] && IS_ROOT=1
    detect_os
    _m_user=$(id -un 2>/dev/null || echo "uid $(id -u)")
    printf '%sphp2shell-check %s%s  %s + %s (PHP RCE, CVSS 9.2)\n' "$BLD" "$SCRIPT_VERSION" "$RST" "$CVE_A" "$CVE_B"
    printf 'Host:   %s | %s | %s | user %s\n' "$(uname -n)" "$OS_NAME" "$(uname -m)" "$_m_user"
    printf 'Fixed:  %s (8.1 and older: EOL, no upstream fix)\n' "$(echo "$FIXED_RELEASES" | sed 's/ /, /g')"
    if [ "$IS_ROOT" = 0 ]; then
        printf '%sNot root: other users'"'"' processes, containers and some paths may be missed. Re-run with sudo.%s\n' "$YEL" "$RST"
    fi
    echo

    collect_static
    collect_processes
    [ "$DEEP" = 1 ] && collect_deep
    while IFS="$TAB" read -r _m_kind _m_real _m_orig; do
        check_install "$_m_kind" "$_m_real" "$_m_orig"
    done <"$TMP/cands"
    scan_containers
    print_results
    report_stale

    _m_total=$((N_VULN + N_OK + N_UNK))
    [ "$_m_total" = 0 ] && echo "No PHP installation found."
    echo
    printf '%sSummary:%s %s PHP installation(s): %s%s vulnerable%s, %s patched, %s undetermined, %s stale worker(s)\n' \
        "$BLD" "$RST" "$_m_total" "$RED" "$N_VULN" "$RST" "$N_OK" "$N_UNK" "$N_STALE"
    [ -n "$CTR_NOTE" ] && printf 'Containers:%s\n' "$CTR_NOTE"
    if [ $((N_VULN + N_STALE)) -gt 0 ]; then
        printf '%s' "$DIM"
        echo "After updating, restart php-fpm / apache2 (httpd) / frankenphp: old code keeps running until then."
        echo "Updating is the only complete fix. Partial workarounds (e.g. session.upload_progress.enabled=0):"
        echo "  $ADVISORY_A"
        echo "  $ADVISORY_B"
        printf '%s' "$RST"
    fi
    echo "RESULT host=$(uname -n) vulnerable=$N_VULN patched=$N_OK unknown=$N_UNK stale=$N_STALE"

    [ $((N_VULN + N_STALE)) -gt 0 ] && exit 1
    [ "$N_UNK" -gt 0 ] && exit 2
    exit 0
}

main "$@"
