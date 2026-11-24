#!/usr/bin/env bash
# bawls installer: Apache or nginx on Debian/Ubuntu, as root.
#
#   sudo ./install.sh --config bawls.conf    first install (see bawls.conf.example)
#   sudo ./install.sh                         re-apply /etc/bawls/bawls.conf, or
#                                             upgrade when run from a newer release
#   sudo ./install.sh --check                 health check; changes nothing
#   sudo ./install.sh --allow-my-ip           your IP changed: let the console in from
#                                             the one this SSH session comes from
#   sudo ./install.sh --uninstall [--purge]   remove bawls; --purge deletes its data too
#
# Safe to run again: it only changes what differs from the config, and says
# what it changed. An upgrade backs up the code, database, .env and config
# first and rolls back by itself if anything fails. Run it from an unpacked
# release (deploy/build-release.sh), which carries vendor/ and public/build,
# so the server needs no Composer or Node.
set -Eeuo pipefail
umask 022
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ETC=/etc/bawls
CONF="$ETC/bawls.conf"
STATE=/var/lib/bawls
# fail2ban's bans for the console's Lists page; the bawls-bans unit's
# StateDirectory and config('bawls.ban.export') both name this path.
BAN_EXPORT="$STATE/bans/banned.txt"
CREDENTIALS=/root/bawls-console.txt
# The user the app runs as (its PHP-FPM pool, the scheduler, artisan): see configure_app_user.
APP_USER=bawls
APP_GROUP=bawls
MANAGED="Managed by the bawls installer. Edit $CONF and re-run install.sh, not this file."

KNOWN_KEYS=(INSTALL_DIR WEB_SERVER CONSOLE_HOST CONSOLE_ALLOW ADMIN_EMAIL DECOY_MODE DECOY_DOMAINS
    REPLACE_DEFAULT_VHOST LETSENCRYPT LETSENCRYPT_EMAIL THEME BAN BAN_TIME NEVER_BLOCK UFW_SENSOR
    MAXMIND_LICENSE_KEY ALERT_WEBHOOK INSTALL_PACKAGES DECOY_PORT INGEST_PORT PHP_VERSION
    SITE_LOGS SITE_BAN)

PHP_EXTENSIONS=(ctype curl dom fileinfo filter hash iconv json libxml mbstring openssl pcre
    session tokenizer pdo_sqlite)

CHANGES=()               # human-readable list of what this run changed
declare -A CHANGED=()    # flags: code env decoy sched ufw sites web f2b bans (env: .env changed)
WEB_BACKUPS=()           # "dest|backup" (backup "-" = the file was new)
WEB_ENABLED=()
WEB_DISABLED=()
BACKUP_DIR=""            # set once an upgrade has backed up the old install
ROLLING_BACK=no
CHECK_FAILED=0
# The services bawls installs, and for each the CHANGED tag its files are
# installed under (a changed file restarts its service). Everything that
# starts, checks, rolls back or removes them reads this one list; whether an
# optional one is wanted on this server is unit_wanted's to say.
UNITS=(bawls-decoy bawls-scheduler bawls-ufw-sensor bawls-site-sensor)
declare -A UNIT_TAG=([bawls-decoy]=decoy [bawls-scheduler]=sched [bawls-ufw-sensor]=ufw [bawls-site-sensor]=sites)

unit_wanted() {
    case $1 in
        bawls-ufw-sensor) [[ $UFW_ON == yes ]] ;;
        bawls-site-sensor) [[ $SITE_ON == yes ]] ;;
        *) return 0 ;;
    esac
}
DISABLED_SITES="$STATE/disabled-sites"   # stock sites bawls disabled, for uninstall
EDITED_SITES="$STATE/edited-sites"       # "file|backup": nginx defaults bawls edited

# ---------------------------------------------------------------- output

say()  { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
note_change() { CHANGES+=("$1"); say "  changed: $1"; }

die() {
    printf '\nERROR: %s\n' "$*" >&2
    roll_back
    exit 1
}

on_error() {
    printf '\nERROR: install.sh stopped at line %s: %s\n' "$1" "$2" >&2
    roll_back
    # Stop here. roll_back switches errexit off to do its work; without this
    # the rest of the install would carry on, on top of what was just restored.
    exit 1
}

usage() {
    sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# ---------------------------------------------------------------- helpers

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK:?}"' EXIT

# Template rendering and KEY=value file edits, in Python (always present:
# the sensors need it) so values with any characters are handled safely.
cat > "$WORK/helper.py" <<'PY'
import os, re, sys

def render(path):
    out = []
    for line in open(path).read().splitlines(keepends=True):
        only = re.fullmatch(r"\{\{([A-Z0-9_]+)\}\}\n?", line)
        if only and os.environ.get("V_" + only.group(1)) == "":
            continue  # an optional line, e.g. THEME_BIND, that isn't needed
        def value(m):
            v = os.environ.get("V_" + m.group(1))
            if v is None:
                sys.exit(f"{path}: no value for {{{{{m.group(1)}}}}}")
            return v
        out.append(re.sub(r"\{\{([A-Z0-9_]+)\}\}", value, line))
    sys.stdout.write("".join(out))

def kv_get(path, key):
    if not os.path.exists(path):
        return
    for line in open(path):
        m = re.match(rf"\s*{re.escape(key)}=(.*)$", line.rstrip("\n"))
        if m:
            v = m.group(1).strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1].replace('\\"', '"').replace("\\\\", "\\")
            print(v)
            return

def kv_set(path, key, value):
    if re.search(r"[\s#\"'\\$]", value):
        value = '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    lines = open(path).read().splitlines() if os.path.exists(path) else []
    new, done = [], False
    for line in lines:
        if re.match(rf"\s*{re.escape(key)}=", line):
            if not done:
                new.append(f"{key}={value}")
                done = True
            continue
        new.append(line)
    if not done:
        new.append(f"{key}={value}")
    if new != lines:
        with open(path, "w") as f:
            f.write("\n".join(new) + "\n")
        print("changed")

cmd, *args = sys.argv[1:]
{"render": render, "kv-get": kv_get, "kv-set": kv_set}[cmd](*args)
PY

py() { python3 -I "$WORK/helper.py" "$@"; }
kv_get() { py kv-get "$1" "$2"; }
# kv_set FILE KEY VALUE -> prints "changed" when the file was rewritten
kv_set() { py kv-set "$1" "$2" "$3"; }

rand_hex()  { python3 -I -c 'import secrets, sys; print(secrets.token_hex(int(sys.argv[1])))' "$1"; }
rand_password() {
    python3 -I -c '
import secrets, string
pool = string.ascii_letters + string.digits
while True:
    p = "".join(secrets.choice(pool) for _ in range(20))
    if any(c.isdigit() for c in p) and any(c.isalpha() for c in p):
        print(p)
        break'
}

# install_file SRC DEST MODE GROUP TAG: install SRC at DEST if it differs.
# Sets the TAG flag and records the change; apache files are backed up first
# so a failed config test can be rolled back.
install_file() {
    local src=$1 dest=$2 mode=$3 group=$4 tag=$5
    if [[ -f $dest ]] && cmp -s "$src" "$dest" \
        && [[ $(stat -c '%a %G' "$dest") == "${mode#0} $group" ]]; then
        return 0
    fi
    if [[ $tag == web ]]; then
        local backup="-"
        if [[ -f $dest ]]; then
            backup="$WORK/backup$(printf '%s' "$dest" | tr / _)"
            cp -p "$dest" "$backup"
        fi
        WEB_BACKUPS+=("$dest|$backup")
    fi
    install -D -m "$mode" -o root -g "$group" "$src" "$dest"
    CHANGED[$tag]=1
    note_change "$dest"
}

# render TEMPLATE DEST MODE GROUP TAG, with the template's {{VARS}} taken
# from V_* variables.
render() {
    local out="$WORK/rendered"
    py render "$SRC_DIR/deploy/templates/$1" > "$out" || die "could not render $1"
    install_file "$out" "$2" "$3" "$4" "$5"
}

artisan() {
    (cd "$INSTALL_DIR" && runuser -u "$APP_USER" -- "$PHP_BIN" artisan "$@" --no-interaction)
}

# sqlite_copy FROM TO: SQLite's online backup, consistent even while the app is writing.
sqlite_copy() {
    python3 -I -c 'import sqlite3, sys; sqlite3.connect(sys.argv[1]).backup(sqlite3.connect(sys.argv[2]))' "$1" "$2"
}

is_ipv4() { [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; }
is_ip()   { is_ipv4 "$1" || [[ $1 =~ ^[0-9A-Fa-f:]+(/[0-9]{1,3})?$ && $1 == *:* ]]; }

# The value of an SSH_* variable for this session. sudo strips them from the
# environment, so look in the parent processes (the shell that ran sudo).
ssh_session_var() {
    local var=$1 pid=$$ value
    while [[ -n $pid && $pid -gt 1 ]]; do
        value="$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | sed -n "s/^$var=//p" | head -n1)" || true
        if [[ -n $value ]]; then
            printf '%s\n' "$value"
            return 0
        fi
        pid="$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')" || return 0
    done
}

# ---------------------------------------------------------------- config

parse_args() {
    CONFIG_ARG="" MODE=install PURGE=no ASSUME_YES=no ALLOW_ME=no
    while [[ $# -gt 0 ]]; do
        case $1 in
            --config) [[ $# -ge 2 ]] || usage 1; CONFIG_ARG=$2; shift 2 ;;
            --config=*) CONFIG_ARG=${1#*=}; shift ;;
            --check) MODE=check; shift ;;
            --allow-my-ip) ALLOW_ME=yes; shift ;;
            --uninstall) MODE=uninstall; shift ;;
            --purge) PURGE=yes; shift ;;
            --yes) ASSUME_YES=yes; shift ;;
            -h|--help) usage 0 ;;
            *) say "Unknown option: $1"; usage 1 ;;
        esac
    done
    [[ $PURGE == no || $MODE == uninstall ]] || die "--purge only goes with --uninstall"
    [[ -z $CONFIG_ARG || $MODE == install ]] || die "--config only goes with an install"
    [[ $ALLOW_ME == no || $MODE == install ]] || die "--allow-my-ip only goes with an install"
}

load_config() {  # load_config FILE [NAME]: NAME is what errors call it
    local file=$1 name=${2:-$1} line key value n=0
    while IFS= read -r line || [[ -n $line ]]; do
        n=$((n + 1))
        [[ $line =~ ^[[:space:]]*(#.*)?$ ]] && continue
        [[ $line =~ ^[[:space:]]*([A-Z_][A-Z0-9_]*)=(.*)$ ]] || die "$name line $n: expected KEY=value"
        key=${BASH_REMATCH[1]}
        value=${BASH_REMATCH[2]}
        if [[ $value =~ ^\"(.*)\"[[:space:]]*$ || $value =~ ^\'(.*)\'[[:space:]]*$ ]]; then
            value=${BASH_REMATCH[1]}
        else
            value=${value%%[[:space:]]#*}
            value=${value%"${value##*[![:space:]]}"}
        fi
        [[ " ${KNOWN_KEYS[*]} " == *" $key "* ]] || die "$name line $n: unknown setting $key"
        printf -v "$key" '%s' "$value"
    done < "$file"
}

apply_defaults() {
    local key
    for key in "${KNOWN_KEYS[@]}"; do
        [[ -v $key ]] || printf -v "$key" '%s' ""
    done
    : "${INSTALL_DIR:=/var/www/bawls}"
    : "${WEB_SERVER:=auto}"
    : "${CONSOLE_HOST:=bawls.admin}"
    : "${ADMIN_EMAIL:=admin@$CONSOLE_HOST}"
    : "${DECOY_MODE:=catchall}"
    : "${REPLACE_DEFAULT_VHOST:=no}"
    # 0.1.0 had no LETSENCRYPT switch: an email meant yes.
    if [[ -z $LETSENCRYPT ]]; then
        if [[ -n $LETSENCRYPT_EMAIL && $DECOY_MODE != catchall ]]; then LETSENCRYPT=yes; else LETSENCRYPT=no; fi
    fi
    : "${THEME:=bawls-inc}"
    : "${BAN:=yes}"
    : "${BAN_TIME:=7d}"
    : "${UFW_SENSOR:=auto}"
    : "${SITE_BAN:=yes}"
    : "${INSTALL_PACKAGES:=yes}"
    : "${DECOY_PORT:=8088}"
    : "${INGEST_PORT:=9119}"
    INSTALL_DIR=${INSTALL_DIR%/}
}

validate_config() {
    local value
    [[ $INSTALL_DIR =~ ^/[A-Za-z0-9._/-]+$ ]] || die "INSTALL_DIR must be an absolute path without spaces"
    INSTALL_PARENT="$(dirname "$INSTALL_DIR")"
    [[ $INSTALL_PARENT != / ]] || die "INSTALL_DIR needs a parent directory (e.g. /var/www/bawls)"
    case "$INSTALL_DIR/" in
        /home/*|/root/*|/tmp/*|/run/*|/etc/*|/usr/*|/boot/*|/dev/*|/proc/*|/sys/*)
            die "INSTALL_DIR can't live under $(cut -d/ -f2 <<< "$INSTALL_DIR")/; use /var/www, /srv or /opt" ;;
    esac
    [[ $CONSOLE_HOST =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || die "CONSOLE_HOST must be a lowercase hostname"
    [[ $ADMIN_EMAIL =~ ^[^@[:space:]]+@[^@[:space:]]+$ ]] || die "ADMIN_EMAIL isn't an email address"
    case $WEB_SERVER in auto|apache|nginx) ;; *) die "WEB_SERVER must be auto, apache or nginx" ;; esac
    case $DECOY_MODE in catchall|domain|both) ;; *) die "DECOY_MODE must be catchall, domain or both" ;; esac
    if [[ $DECOY_MODE != catchall ]]; then
        [[ -n $DECOY_DOMAINS ]] || die "DECOY_MODE=$DECOY_MODE needs DECOY_DOMAINS"
        for value in $DECOY_DOMAINS; do
            [[ $value =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || die "bad decoy domain: $value"
        done
    fi
    for value in BAN INSTALL_PACKAGES REPLACE_DEFAULT_VHOST LETSENCRYPT SITE_BAN; do
        [[ ${!value} == yes || ${!value} == no ]] || die "$value must be yes or no"
    done
    case $UFW_SENSOR in auto|yes|no) ;; *) die "UFW_SENSOR must be auto, yes or no" ;; esac
    local name path seen=" "
    for value in $SITE_LOGS; do
        name=${value%%=*} path=${value#*=}
        [[ $seen != *" $path "* ]] || die "SITE_LOGS lists $path twice (one site's http and https logs can share a name)"
        seen+="$path "
        [[ $value == *=* && $name =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] \
            || die "SITE_LOGS takes name=path pairs (name a lowercase hostname), not: $value"
        [[ $path =~ ^/var/log/[A-Za-z0-9._/-]+$ && $path != *..* ]] \
            || die "SITE_LOGS: $name's log must be a path under /var/log, not: $path"
    done
    [[ $BAN_TIME =~ ^[0-9]+[smhdw]?$ ]] || die "BAN_TIME must look like 12h or 7d"
    for value in DECOY_PORT INGEST_PORT; do
        [[ ${!value} =~ ^[0-9]+$ && ${!value} -ge 1024 && ${!value} -le 65535 ]] || die "$value must be a port from 1024 to 65535"
    done
    [[ $DECOY_PORT != "$INGEST_PORT" ]] || die "DECOY_PORT and INGEST_PORT must differ"
    for value in $CONSOLE_ALLOW $NEVER_BLOCK; do
        is_ip "$value" || die "not an IP address: $value"
    done
    [[ -z $LETSENCRYPT_EMAIL || $LETSENCRYPT_EMAIL =~ ^[^@[:space:]]+@[^@[:space:]]+$ ]] || die "LETSENCRYPT_EMAIL isn't an email address"
    [[ $LETSENCRYPT == no || $DECOY_MODE != catchall ]] \
        || die "LETSENCRYPT=yes is for DECOY_DOMAINS, so it needs DECOY_MODE=domain or both"
    [[ -z $PHP_VERSION || $PHP_VERSION =~ ^[0-9]+\.[0-9]+$ ]] \
        || die "PHP_VERSION must look like 8.4, or be empty for the default php"
    # The PHP command line to use: php8.5 when PHP_VERSION=8.5, else plain php.
    PHP_CMD=php${PHP_VERSION}
}

read_config() {  # read_config [FILE [NAME]]: default the installed config
    local file=${1:-$CONF}
    unset "${KNOWN_KEYS[@]}"   # only the config file decides, never the environment
    if [[ -f $file ]]; then
        load_config "$file" "${2:-$file}"
    fi
    apply_defaults
}

# Keep the config at /etc/bawls/bawls.conf, the one later runs read. A new
# config is checked before it replaces the installed one, so a typo can't
# leave the server with a config that no longer works.
settle_config() {
    install -d -m 0755 "$ETC"
    local before="$WORK/conf.before" new="$WORK/conf.new"
    [[ -f $CONF ]] && cp -p "$CONF" "$before" || : > "$before"

    if [[ -n $CONFIG_ARG ]]; then
        [[ -f $CONFIG_ARG ]] || die "no such config file: $CONFIG_ARG"
        cp "$CONFIG_ARG" "$new"
    elif [[ -f $CONF ]]; then
        cp "$CONF" "$new"
    else
        die "no config yet: copy bawls.conf.example, edit it, and run: sudo $0 --config bawls.conf"
    fi
    read_config "$new" "${CONFIG_ARG:-$CONF}"

    # Fill in what was left to detection, and write it back so later runs
    # (from any IP) keep the same answer. --allow-my-ip replaces the list.
    if [[ $ALLOW_ME == yes || -z $CONSOLE_ALLOW ]]; then
        local client
        client="$(ssh_session_var SSH_CLIENT)"
        client=${client%% *}
        is_ip "$client" || die "can't detect your IP (not an SSH session?). Set CONSOLE_ALLOW in the config."
        if [[ -n $CONSOLE_ALLOW ]]; then
            say "  CONSOLE_ALLOW: $CONSOLE_ALLOW -> $client (this SSH session)"
        else
            say "  CONSOLE_ALLOW: detected $client from this SSH session"
        fi
        CONSOLE_ALLOW=$client
        kv_set "$new" CONSOLE_ALLOW "$CONSOLE_ALLOW" >/dev/null
    fi
    validate_config

    if ! cmp -s "$new" "$CONF" || [[ "$(stat -c '%a %U:%G' "$CONF")" != "600 root:root" ]]; then
        install -m 0600 -o root -g root "$new" "$CONF"
    fi
    cmp -s "$before" "$CONF" || note_change "$CONF"
}

# ---------------------------------------------------------------- preflight

preflight() {
    step "Preflight"
    [[ -d /run/systemd/system ]] || die "bawls needs systemd"
    command -v apt-get >/dev/null && command -v dpkg-query >/dev/null \
        || die "this installer supports Debian and Ubuntu (apt) for now"
    resolve_web_server
    [[ -f $SRC_DIR/artisan && -f $SRC_DIR/vendor/autoload.php && -f $SRC_DIR/public/build/manifest.json ]] \
        || die "run this from an unpacked release (deploy/build-release.sh), not a source checkout"
    check_default_vhost
    say "  ok: root, systemd, apt, release files, default site; web server: $WEB_SERVICE"
}

php_ok() {
    command -v "$PHP_CMD" >/dev/null || return 1
    "$PHP_CMD" -r 'exit(PHP_VERSION_ID >= 80401 ? 0 : 1);' 2>/dev/null
}

missing_packages() {
    local missing=() v ext
    web_installed || missing+=("$WEB_SERVICE")
    command -v rsync >/dev/null || missing+=(rsync)
    command -v curl >/dev/null || missing+=(curl)
    command -v openssl >/dev/null || missing+=(openssl)
    command -v python3 >/dev/null || missing+=(python3)
    if ! command -v "$PHP_CMD" >/dev/null; then
        v=$PHP_VERSION   # php8.5-cli ..., or Debian's default php-cli ...
        missing+=("php$v-cli" "php$v-fpm" "php$v-sqlite3" "php$v-mbstring" "php$v-xml" "php$v-curl")
    elif php_ok; then
        v="$("$PHP_CMD" -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')"
        systemctl cat "php$v-fpm" >/dev/null 2>&1 || missing+=("php$v-fpm")
        for ext in pdo_sqlite mbstring dom curl; do
            "$PHP_CMD" -r "exit(extension_loaded('$ext') ? 0 : 1);" || case $ext in
                pdo_sqlite) missing+=("php$v-sqlite3") ;;
                dom) missing+=("php$v-xml") ;;
                *) missing+=("php$v-$ext") ;;
            esac
        done
    fi
    [[ $BAN == no ]] || command -v fail2ban-client >/dev/null || missing+=(fail2ban)
    if [[ $LETSENCRYPT == yes ]]; then
        command -v certbot >/dev/null || missing+=(certbot)
    fi
    printf '%s\n' "${missing[@]}" | awk 'NF && !seen[$0]++'
}

install_packages() {
    step "Packages"
    local missing
    mapfile -t missing < <(missing_packages)
    if [[ ${#missing[@]} -eq 0 ]]; then
        say "  ok: everything needed is installed"
    elif [[ $INSTALL_PACKAGES == yes ]]; then
        say "  installing: ${missing[*]}"
        export DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1
        apt-get update -q >/dev/null
        apt-get install -y -q "${missing[@]}" >/dev/null
        note_change "packages: ${missing[*]}"
    else
        die "missing packages: ${missing[*]} (apt-get install them, or set INSTALL_PACKAGES=yes)"
    fi

    php_ok || die "PHP 8.4.1 or newer is required (found: $("$PHP_CMD" -r 'echo PHP_VERSION;' 2>/dev/null || echo none)). On a server with several, set PHP_VERSION."
    python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' || die "Python 3.10 or newer is required"
    local ext missing_ext=()
    for ext in "${PHP_EXTENSIONS[@]}"; do
        "$PHP_CMD" -r "exit(extension_loaded('$ext') ? 0 : 1);" || missing_ext+=("$ext")
    done
    [[ ${#missing_ext[@]} -eq 0 ]] || die "PHP is missing extensions: ${missing_ext[*]}"
}

detect_runtime() {
    PHP_VERSION="$("$PHP_CMD" -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')"
    PHP_BIN="/usr/bin/php$PHP_VERSION"
    [[ -x $PHP_BIN ]] || PHP_BIN="$(command -v "$PHP_CMD")"
    PHP_FPM="php$PHP_VERSION-fpm"
    # bawls has a PHP-FPM pool and a user of its own (configure_app_user).
    PHP_POOL="/etc/php/$PHP_VERSION/fpm/pool.d/bawls.conf"
    PHP_FPM_SOCK="/run/php/bawls.sock"
    PYTHON="$(command -v python3)"
    if [[ $WEB_SERVER == apache ]]; then
        read -r WEB_USER WEB_GROUP < <(set +u; . /etc/apache2/envvars; echo "${APACHE_RUN_USER:-www-data} ${APACHE_RUN_GROUP:-www-data}")
    else
        WEB_USER="$(sed -n 's/^[[:space:]]*user[[:space:]]\{1,\}\([^[:space:];]*\).*/\1/p' /etc/nginx/nginx.conf | head -n1)"
        WEB_USER=${WEB_USER:-www-data}
        WEB_GROUP="$(id -gn "$WEB_USER")"
    fi

    mapfile -t SERVER_IPS4 < <(ip -4 -o addr show scope global | awk '{ split($4, a, "/"); print a[1] }')
    mapfile -t SERVER_IPS6 < <(ip -6 -o addr show scope global | awk '{ split($4, a, "/"); print a[1] }')
    SERVER_IP="$(ssh_session_var SSH_CONNECTION | awk '{ print $3 }')"
    [[ -n $SERVER_IP ]] || SERVER_IP="${SERVER_IPS4[0]:-}"
    HOST_SHORT="$(hostname -s)"

    if [[ $THEME == */* ]]; then
        THEME_DIR="$(readlink -f "$THEME")" || die "THEME folder not found: $THEME"
        [[ $THEME_DIR =~ ^/[A-Za-z0-9._/-]+$ ]] || die "THEME must be a path without spaces or special characters: $THEME_DIR"
    else
        [[ $THEME =~ ^[a-z0-9_-]+$ ]] || die "THEME must be a theme name or an absolute path"
        THEME_DIR="$INSTALL_DIR/sensors/themes/$THEME"
    fi
    case "$THEME_DIR/" in
        /home/*|/root/*|/tmp/*) die "the decoy can't read a theme under /home, /root or /tmp; move $THEME_DIR" ;;
        "$INSTALL_DIR/sensors/"*) THEME_BIND="" ;;
        "$INSTALL_DIR/"*) die "keep a custom theme outside $INSTALL_DIR, which upgrades replace" ;;
        "$INSTALL_PARENT/"*) THEME_BIND="BindReadOnlyPaths=$THEME_DIR" ;;
        *) THEME_BIND="" ;;
    esac

    case $UFW_SENSOR in
        yes) UFW_ON=yes ;;
        no) UFW_ON=no ;;
        auto) if command -v ufw >/dev/null && [[ "$(ufw status 2>/dev/null)" == *"Status: active"* ]]; then UFW_ON=yes; else UFW_ON=no; fi ;;
    esac
    SITE_ON=no
    [[ -z $SITE_LOGS ]] || SITE_ON=yes

    say "  PHP $PHP_VERSION (FPM), $("$PYTHON" -V), web user $WEB_USER, app user $APP_USER, server IP ${SERVER_IP:-unknown}"
}

# ---------------------------------------------------------------- app

# configure_app_user: the user bawls runs as ($APP_USER) and its PHP-FPM pool.
#
# The web server's own user is shared by every site on the box, so the app
# doesn't run as it: only $APP_USER can read the database, .env and the ban
# list, and the web server reaches the app through the pool's socket alone.
# An install from before this (owned by the web user) is moved over by
# fix_permissions; the vhosts pick up the new socket in configure_web.
configure_app_user() {
    id "$APP_USER" >/dev/null 2>&1 || {
        useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$APP_USER"
        note_change "user $APP_USER"
    }
    local stale
    for stale in /etc/php/*/fpm/pool.d/bawls.conf; do   # left by another PHP version
        [[ -f $stale && $stale != "$PHP_POOL" ]] || continue
        rm -f "$stale"
        note_change "$stale removed"
    done
    V_MANAGED=$MANAGED V_APP_USER=$APP_USER V_APP_GROUP=$APP_GROUP V_WEB_USER=$WEB_USER \
        V_WEB_GROUP=$WEB_GROUP V_PHP_FPM_SOCK=$PHP_FPM_SOCK \
        render php-fpm-pool.conf.tmpl "$PHP_POOL" 0644 root pool
    systemctl enable --quiet "$PHP_FPM"
    if [[ -n ${CHANGED[pool]:-} ]] || ! systemctl is-active --quiet "$PHP_FPM"; then
        "php-fpm$PHP_VERSION" -t 2>/dev/null || { rm -f "$PHP_POOL"; die "PHP-FPM rejected bawls' pool ($PHP_POOL); removed it again"; }
        # A reload starts the new pool without dropping the other sites' requests.
        systemctl reload-or-restart "$PHP_FPM"
    fi
}

install_code() {
    step "Code -> $INSTALL_DIR"
    configure_app_user
    id bawls-decoy >/dev/null 2>&1 || {
        useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin bawls-decoy
        note_change "user bawls-decoy"
    }

    install -d -m 0755 "$INSTALL_DIR"
    if [[ "$(readlink -f "$SRC_DIR")" != "$(readlink -f "$INSTALL_DIR")" ]]; then
        local itemized
        itemized="$(sync_code "$SRC_DIR" --dry-run)"
        if [[ -n $itemized ]]; then
            [[ ! -f $INSTALL_DIR/artisan ]] || backup_before_upgrade
            sync_code "$SRC_DIR" >/dev/null
            CHANGED[code]=1
            note_change "code ($(wc -l <<< "$itemized") files) from $SRC_DIR, version $(release_version "$SRC_DIR")"
        fi
        rsync -a --ignore-existing --no-owner --no-group "$SRC_DIR/storage/" "$INSTALL_DIR/storage/"
    fi
    [[ -d $THEME_DIR ]] || die "theme not found: $THEME_DIR"

    fix_permissions
}

release_version() { cat "$1/VERSION" 2>/dev/null || echo unknown; }

# sync_code FROM [--dry-run]: make INSTALL_DIR's code match FROM, printing
# what differs. Runtime state is never touched: .env, storage, the database,
# and bootstrap/cache (Laravel rebuilds it). Permissions, bar the executable
# bit, and directory times are left to fix_permissions and the app, so a
# re-run doesn't fight them.
sync_code() {
    rsync -a --no-perms --executability --omit-dir-times --delete \
        --no-owner --no-group --itemize-changes ${2:+"$2"} \
        --exclude=/.env --exclude=/storage/ --exclude='/database/*.sqlite*' \
        --exclude='/bootstrap/cache/*' --exclude=/.git/ --exclude=/node_modules/ \
        "$1/" "$INSTALL_DIR/"
}

# Before replacing an existing install's code: keep its code, database, .env
# and config, so a failed upgrade can be undone (roll_back). The newest three
# backups are kept.
backup_before_upgrade() {
    local dir old db="$INSTALL_DIR/database/database.sqlite"
    old="$(release_version "$INSTALL_DIR")"
    dir="$STATE/backup/upgrade-$(date +%Y%m%d-%H%M%S)"
    say "  upgrading $old -> $(release_version "$SRC_DIR"); backing up to $dir"
    install -d -m 0755 "$STATE"
    install -d -m 0700 "$STATE/backup" "$dir"
    printf '%s\n' "$old" > "$dir/VERSION"
    tar -C "$INSTALL_DIR" --exclude=./storage --exclude='./database/*.sqlite*' \
        --exclude='./bootstrap/cache/*' -czf "$dir/code.tar.gz" .
    cp -p "$WORK/conf.before" "$dir/bawls.conf"
    # Not a symlink: the web user owns that directory, and root follows nothing in it.
    if [[ -f $db && ! -L $db ]]; then
        sqlite_copy "$db" "$dir/database.sqlite"
    fi
    BACKUP_DIR=$dir
    ls -1dt "${STATE:?}"/backup/upgrade-* | tail -n +4 | xargs -r rm -rf
}

# After a failed upgrade: put the backed-up install back and let its own
# installer re-apply it. Runs once, and only in the main shell.
roll_back() {
    [[ -n $BACKUP_DIR && $ROLLING_BACK == no && $BASHPID == "$$" ]] || return 0
    ROLLING_BACK=yes
    trap - ERR
    set +e
    local dir=$BACKUP_DIR old
    old="$(cat "$dir/VERSION")"
    printf '\n== Rolling back to %s (from %s)\n' "$old" "$dir"
    systemctl stop "${UNITS[@]}" 2>/dev/null

    mkdir -p "$WORK/previous"
    tar -xzf "$dir/code.tar.gz" -C "$WORK/previous" && sync_code "$WORK/previous" >/dev/null \
        && cp -p "$WORK/previous/.env" "$INSTALL_DIR/.env" 2>/dev/null
    cp -p "$dir/bawls.conf" "$CONF"
    if [[ -f $dir/database.sqlite ]]; then
        [[ ! -L $INSTALL_DIR/database/database.sqlite ]] || rm -f "$INSTALL_DIR/database/database.sqlite"
        sqlite_copy "$dir/database.sqlite" "$INSTALL_DIR/database/database.sqlite"
    fi
    rm -f "${INSTALL_DIR:?}"/bootstrap/cache/*.php

    if [[ -x $INSTALL_DIR/install.sh ]] && "$INSTALL_DIR/install.sh"; then
        printf '\nRolled back: %s is running again. The failed upgrade is described above.\n' "$old" >&2
    else
        local unit
        for unit in "${UNITS[@]}"; do systemctl start "$unit" 2>/dev/null; done
        printf '\nWARNING: the rollback could not fully re-apply %s. The backup is in %s.\n' "$old" "$dir" >&2
    fi
}

# Code belongs to root. The web user owns only what Laravel writes (storage,
# bootstrap/cache, the SQLite database and its directory), and other local
# users can't read any of that: the database, logs, sessions.
fix_permissions() {
    local d=$INSTALL_DIR decoy_dir="$INSTALL_DIR/storage/app/decoy" dir
    find "$d" \( -path "$d/storage" -o -path "$d/bootstrap/cache" -o -path "$d/.env" \) -prune \
        -o \( ! -path "$d/database" ! -name '*.sqlite*' \) \( ! -user root -o ! -group root \) \
        -exec chown -h root:root {} +
    find "$d" \( -path "$d/storage" -o -path "$d/bootstrap/cache" -o -path "$d/.env" \) -prune \
        -o \( ! -path "$d/database" ! -name '*.sqlite*' ! -type l \) \
        \( ! -perm -u+r -o ! -perm -go+r -o -perm /go+w -o \( -type d ! -perm -go+x \) \) \
        -exec chmod u+rwX,go+rX,go-w {} +
    for dir in storage bootstrap/cache; do
        install -d "$d/$dir"
        chown -R "$APP_USER:$APP_GROUP" "$d/$dir"
        # ! -type l: chmod follows a symlink to its target, and the web user
        # can plant one here (chown -R above does not follow them).
        find "$d/$dir" -path "$decoy_dir" -prune -o ! -type l -exec chmod u+rwX,g+rwX,o-rwx {} +
    done
    chown "$APP_USER:$APP_GROUP" "$d/database"
    chmod 0770 "$d/database"
    # -type f and -h for the same reason: only real files, never a link's target.
    find "$d/database" -maxdepth 1 -type f -name '*.sqlite*' -exec chown -h "$APP_USER:$APP_GROUP" {} + \
        -exec chmod 0660 {} +
    # Except the /browser-check flag, which the decoy (another user) reads.
    install -d -m 2775 -o "$APP_USER" -g "$APP_GROUP" "$decoy_dir"
    find "$decoy_dir" -type f -exec chmod 0644 {} +
}

write_env() {
    step "Laravel"
    local env="$INSTALL_DIR/.env" fresh=no
    if [[ ! -f $env ]]; then
        cp "$INSTALL_DIR/.env.example" "$env"
        fresh=yes
        kv_set "$env" APP_ENV production >/dev/null
        kv_set "$env" APP_DEBUG false >/dev/null
        kv_set "$env" SESSION_SECURE_COOKIE true >/dev/null
    fi
    chown root:"$APP_GROUP" "$env"
    chmod 0640 "$env"

    [[ -n "$(kv_get "$env" APP_KEY)" ]] \
        || kv_set "$env" APP_KEY "base64:$(head -c 32 /dev/urandom | base64)" >/dev/null
    local slug
    slug="$(kv_get "$env" BAWLS_LOGIN_PATH)"
    if [[ -z $slug || $slug == login ]]; then
        kv_set "$env" BAWLS_LOGIN_PATH "$(rand_hex 12)" >/dev/null
    fi

    local never=() ip
    for ip in "${SERVER_IPS4[@]}" $CONSOLE_ALLOW $NEVER_BLOCK; do
        is_ipv4 "$ip" && never+=("$ip")
    done
    local -A managed=(
        [APP_URL]="https://$CONSOLE_HOST"
        [BAWLS_BAN_ENABLED]="$([[ $BAN == yes ]] && echo true || echo false)"
        [BAWLS_SITE_BAN]="$([[ $SITE_BAN == yes ]] && echo true || echo false)"
        [BAWLS_NEVER_BLOCK]="$(printf '%s\n' "${never[@]}" | awk '!seen[$0]++' | paste -sd, -)"
    )
    # Only when set: these two may also be set straight in .env (installs from
    # before bawls.conf had them do), and an empty value here must not wipe
    # that. To clear one, remove it from both files.
    [[ -z $MAXMIND_LICENSE_KEY ]] || managed[MAXMIND_LICENSE_KEY]=$MAXMIND_LICENSE_KEY
    [[ -z $ALERT_WEBHOOK ]] || managed[BAWLS_ALERT_WEBHOOK]=$ALERT_WEBHOOK
    local key env_changed=no
    for key in "${!managed[@]}"; do
        [[ -z "$(kv_set "$env" "$key" "${managed[$key]}")" ]] || env_changed=yes
    done
    if [[ $fresh == yes ]]; then
        note_change "$env (new: app key and secret sign-in path generated)"
    elif [[ $env_changed == yes ]]; then
        note_change "$env"
    fi
    # Laravel copies .env into its process environment, which children
    # inherit and later reads never override, so a long-running process keeps
    # the old values until it restarts (see configure_services).
    [[ $fresh == no && $env_changed == no ]] || CHANGED[env]=1
    # New code may bring new packages: drop Laravel's caches so they rebuild.
    [[ -z ${CHANGED[code]:-} ]] || rm -f "${INSTALL_DIR:?}"/bootstrap/cache/*.php

    local db="$INSTALL_DIR/database/database.sqlite"
    [[ -f $db ]] || runuser -u "$APP_USER" -- touch "$db"
    local migrated
    migrated="$(artisan migrate --force)"
    if ! grep -q 'Nothing to migrate' <<< "$migrated"; then
        note_change "database migrations"
    fi

    if [[ -n $MAXMIND_LICENSE_KEY ]] && ! compgen -G "$INSTALL_DIR/storage/geoip/*.mmdb" >/dev/null; then
        if artisan bawls:geoip-update >/dev/null 2>&1; then
            note_change "GeoLite2 databases downloaded"
        else
            warn "GeoLite2 download failed (check MAXMIND_LICENSE_KEY); the scheduler retries weekly"
        fi
    fi
}

# sensor_token VAR NAME KIND ENVFILE: put the token already in ENVFILE into
# VAR, or issue one. (Sets a variable rather than printing, so the change it
# notes isn't lost in a subshell.)
sensor_token() {
    local -n token_ref=$1
    local name=$2 kind=$3 envfile=$4
    token_ref="$(kv_get "$envfile" TRIPWIRE_TOKEN)"
    if [[ ! $token_ref =~ ^[A-Za-z0-9]{48}$ ]]; then
        token_ref="$(artisan bawls:sensor "$name" --kind="$kind" --rotate --token-only | tail -n1)"
        [[ $token_ref =~ ^[A-Za-z0-9]{48}$ ]] || die "could not register sensor $name"
        note_change "sensor $name registered"
    fi
}

# remove_unit UNIT WHY [FILE...]: stop and remove a service bawls installed,
# and the files that go with it. Does nothing when it isn't installed.
remove_unit() {
    local unit=$1 why=$2
    shift 2
    [[ -f /etc/systemd/system/$unit.service ]] || return 0
    systemctl disable --now --quiet "$unit" 2>/dev/null || true
    rm -f "/etc/systemd/system/${unit:?}.service" "$@"
    systemctl daemon-reload
    note_change "$unit removed${why:+ ($why)}"
}

# write_credentials PASSWORD: the console's address, login and hosts line,
# root-only. Rewritten only when something in it changed.
write_credentials() {
    local slug text="$WORK/credentials" server=${SERVER_IP:-SERVER_IP}
    slug="$(kv_get "$INSTALL_DIR/.env" BAWLS_LOGIN_PATH)"
    {
        printf 'bawls console. Keep this file private.\n\n'
        printf 'Console:   https://%s/%s\n' "$CONSOLE_HOST" "$slug"
        printf 'Email:     %s\n' "$ADMIN_EMAIL"
        printf 'Password:  %s\n\n' "$1"
        printf 'Add this line to the hosts file of each computer you use the console from\n'
        printf '(/etc/hosts, or C:\\Windows\\System32\\drivers\\etc\\hosts on Windows):\n\n'
        printf '    %s  %s\n\n' "$server" "$CONSOLE_HOST"
        printf 'The certificate is self-signed, so your browser warns once.\n'
        printf 'Allowed from: %s, and 127.0.0.1 for an SSH tunnel:\n' "$CONSOLE_ALLOW"
        printf '    ssh -L 8443:127.0.0.1:443 you@%s\n' "$server"
        printf '    then https://%s:8443/%s with %s -> 127.0.0.1 in your hosts file\n' \
            "$CONSOLE_HOST" "$slug" "$CONSOLE_HOST"
    } > "$text"
    if ! cmp -s "$text" "$CREDENTIALS"; then
        install -m 0600 -o root -g root "$text" "$CREDENTIALS"
        note_change "$CREDENTIALS"
    fi
}

# console_user: make sure ADMIN_EMAIL can sign in, and that the credentials
# file describes that login. `bawls:user --keep` creates the user only when it
# doesn't exist, so this is safe on every run, and a changed ADMIN_EMAIL gets
# its own user and password rather than the old one's password under a new name.
console_user() {
    local candidate output password stored_email="" stored_password=""
    if [[ -f $CREDENTIALS ]]; then
        stored_email="$(sed -n 's/^Email: *//p' "$CREDENTIALS")"
        stored_password="$(sed -n 's/^Password: *//p' "$CREDENTIALS")"
    fi
    candidate="$(rand_password)"
    output="$(cd "$INSTALL_DIR" && BAWLS_USER_PASSWORD="$candidate" \
        runuser -u "$APP_USER" -- "$PHP_BIN" artisan bawls:user "$ADMIN_EMAIL" --keep --no-interaction)" \
        || die "could not create the console user: $output"
    if ! grep -q 'left unchanged' <<< "$output"; then
        password=$candidate
        note_change "console user $ADMIN_EMAIL"
    elif [[ $stored_email == "$ADMIN_EMAIL" && -n $stored_password ]]; then
        password=$stored_password
    else
        password="(unchanged: $ADMIN_EMAIL already existed. Reset: sudo -u $APP_USER $PHP_BIN $INSTALL_DIR/artisan bawls:user $ADMIN_EMAIL)"
    fi
    write_credentials "$password"
}

# ---------------------------------------------------------------- web server
#
# Apache and nginx are driven through the same few functions. Site files
# have the same names under both: 000-bawls-catchall.conf (first, the
# default), bawls-ingest.conf, bawls-decoy.conf, zz-bawls-console.conf.

# WEB_SERVER=auto picks the one that's installed (Apache when neither is).
resolve_web_server() {
    local has_apache=no has_nginx=no other
    command -v apache2ctl >/dev/null && has_apache=yes
    command -v nginx >/dev/null && has_nginx=yes
    if [[ $WEB_SERVER == auto ]]; then
        if [[ $has_apache == yes && $has_nginx == yes ]]; then
            if systemctl is-active --quiet nginx && ! systemctl is-active --quiet apache2; then
                WEB_SERVER=nginx
            elif systemctl is-active --quiet apache2 && ! systemctl is-active --quiet nginx; then
                WEB_SERVER=apache
            else
                die "both Apache and nginx are installed; set WEB_SERVER=apache or nginx in $CONF"
            fi
        elif [[ $has_nginx == yes ]]; then
            WEB_SERVER=nginx
        else
            WEB_SERVER=apache
        fi
    fi
    if [[ $WEB_SERVER == apache ]]; then
        WEB_SERVICE=apache2 other=nginx
    else
        WEB_SERVICE=nginx other=apache2
    fi
    SITES_AVAILABLE="/etc/$WEB_SERVICE/sites-available"
    SITES_ENABLED="/etc/$WEB_SERVICE/sites-enabled"
    if systemctl is-active --quiet "$other" 2>/dev/null; then
        die "$other is running, but bawls is set up for $WEB_SERVICE, and only one can own ports 80 and 443. Set WEB_SERVER in $CONF to the one this server uses."
    fi
}

web_installed() {
    if [[ $WEB_SERVER == apache ]]; then command -v apache2ctl >/dev/null; else command -v nginx >/dev/null; fi
}

web_configtest() {
    if [[ $WEB_SERVER == apache ]]; then apache2ctl configtest 2>&1; else nginx -t 2>&1; fi
}

self_signed() {  # self_signed NAME CN -> /etc/ssl/bawls/NAME.{crt,key}
    local name=$1 cn=$2 crt="/etc/ssl/bawls/$1.crt" key="/etc/ssl/bawls/$1.key"
    install -d -m 0755 /etc/ssl/bawls
    if [[ -f $crt && "$(openssl x509 -in "$crt" -noout -subject 2>/dev/null)" =~ CN\ ?=\ ?$cn$ ]]; then
        return 0
    fi
    openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes -subj "/CN=$cn" \
        -addext "subjectAltName=DNS:$cn" -keyout "$key" -out "$crt" 2>/dev/null
    chmod 0600 "$key"
    CHANGED[web]=1
    note_change "$crt (self-signed, CN=$cn)"
}

# The file behind the web server's default site for PORT, read from the
# config on disk (so it can be checked before a reload), or nothing.
default_site_file() {
    local dump
    if [[ $WEB_SERVER == apache ]]; then
        dump="$(apache2ctl -S 2>/dev/null)" || true
        awk -v addr="*:$1" '
            $1 == addr && /NameVirtualHost/ { named = 1; next }
            named && /default server/ { print; exit }
            $1 == addr { print; exit }' <<< "$dump" | sed -n 's/.*(\(.*\):[0-9]*)$/\1/p'
    else
        # nginx: the server marked default_server for the port, else the
        # first one that listens on it.
        dump="$(nginx -T 2>/dev/null)" || true
        awk -v port="$1" '
            /^# configuration file / { file = $4; sub(/:$/, "", file); next }
            /^[[:space:]]*#/ { next }
            $1 == "listen" {
                addr = $2; sub(/;$/, "", addr); n = split(addr, part, ":")
                if (part[n] == port) {
                    if (first == "") first = file
                    if (def == "" && $0 ~ /default_server/) def = file
                }
            }
            END { if (def != "") print def; else if (first != "") print first }' <<< "$dump"
    fi | xargs -r readlink -f
}

# True when FILE is exactly as its Debian package shipped it.
is_stock_file() {
    local pkg want
    pkg="$(dpkg -S "$1" 2>/dev/null | head -n1 | cut -d: -f1)" || true
    [[ -n $pkg ]] || return 1
    want="$(dpkg-query -W -f='${Conffiles}\n' "$pkg" 2>/dev/null | awk -v f="$1" '$1 == f { print $2 }')"
    [[ -n $want && "$(md5sum < "$1" | cut -d' ' -f1)" == "$want" ]]
}

# nginx_unlink FILE: remove one sites-enabled link (never a real file).
nginx_unlink() {
    local link="${SITES_ENABLED:?}/${1:?}"
    [[ -L $link ]] || die "$link is a file, not a link; not removing it"
    unlink "$link"
}

enable_site() {  # enable_site FILE: a file name in SITES_AVAILABLE
    [[ -e $SITES_ENABLED/$1 ]] && return 0
    if [[ $WEB_SERVER == apache ]]; then
        a2ensite -q "$1" >/dev/null
    else
        ln -s "$SITES_AVAILABLE/$1" "$SITES_ENABLED/$1"
    fi
    WEB_ENABLED+=("$1")
    CHANGED[web]=1
    note_change "$WEB_SERVICE site $1 enabled"
}

disable_site() {
    [[ -e $SITES_ENABLED/$1 ]] || return 0
    if [[ $WEB_SERVER == apache ]]; then
        a2dissite -q "$1" >/dev/null
    else
        nginx_unlink "$1"
    fi
    WEB_DISABLED+=("$1")
    CHANGED[web]=1
    note_change "$WEB_SERVICE site $1 disabled"
}

rollback_web() {
    local entry dest backup site
    for entry in "${WEB_BACKUPS[@]}"; do
        dest=${entry%%|*}
        backup=${entry#*|}
        if [[ $backup == - ]]; then unlink "$dest" 2>/dev/null || true; else cp -p "$backup" "$dest"; fi
    done
    for site in "${WEB_ENABLED[@]}"; do
        if [[ $WEB_SERVER == apache ]]; then a2dissite -q "$site" >/dev/null || true; else nginx_unlink "$site" || true; fi
    done
    for site in "${WEB_DISABLED[@]}"; do
        if [[ $WEB_SERVER == apache ]]; then a2ensite -q "$site" >/dev/null || true; else ln -sf "$SITES_AVAILABLE/$site" "$SITES_ENABLED/$site"; fi
    done
    WEB_BACKUPS=() WEB_ENABLED=() WEB_DISABLED=()
}

# The sites that are the web server's default for port 80 or 443 today, as
# "PORT FILE STOCK" lines, leaving out bawls' own.
current_defaults() {
    web_installed || return 0
    local port file
    for port in 80 443; do
        file="$(default_site_file "$port")"
        case $file in
            ""|*/000-bawls-catchall.conf|*/zz-bawls-console.conf|*/bawls-decoy.conf) continue ;;
        esac
        if is_stock_file "$file"; then echo "$port $file yes"; else echo "$port $file no"; fi
    done
}

# Taking over the catch-all replaces Debian's stock page freely, but a site
# someone set up only with REPLACE_DEFAULT_VHOST=yes. Never silently.
# Checked in preflight, before anything is installed.
check_default_vhost() {
    [[ $DECOY_MODE != domain && $REPLACE_DEFAULT_VHOST == no ]] || return 0
    local defaults line port file stock
    mapfile -t defaults < <(current_defaults)
    for line in "${defaults[@]}"; do
        read -r port file stock <<< "$line"
        [[ $stock == no ]] || continue
        die "port $port's default site is $file, which isn't Debian's stock page.
DECOY_MODE=$DECOY_MODE would make bawls the default instead: every request for
an unknown host or the bare IP would get the decoy, not that site. bawls has not
installed anything yet. If that's what you want, set REPLACE_DEFAULT_VHOST=yes in
$CONF and re-run (the file is backed up first). Otherwise use DECOY_MODE=domain."
    done
}

# remember LIST LINE: add LINE to the state file LIST once (for uninstall).
remember() {
    install -d -m 0755 "$STATE"
    grep -qxF "$2" "$1" 2>/dev/null || printf '%s\n' "$2" >> "$1"
}

claim_default_vhost() {
    local defaults line port file stock backup
    mapfile -t defaults < <(current_defaults)
    for line in "${defaults[@]}"; do
        read -r port file stock <<< "$line"
        if [[ $stock == yes ]]; then
            disable_site "$(basename "$file")"
            remember "$DISABLED_SITES" "$WEB_SERVER $(basename "$file")"
            continue
        fi
        if [[ $REPLACE_DEFAULT_VHOST != yes ]]; then
            rollback_web
            die "port $port's default site is $file, which isn't Debian's stock page (rolled back)."
        fi
        install -d -m 0700 "$STATE/backup"
        backup="$STATE/backup/$(basename "$file").$(date +%Y%m%d%H%M%S)"
        cp -p "$file" "$backup"
        say "  port $port: taking over the default from $file (backed up to $backup)."
        say "  It still answers its own server name; unknown hosts now get the decoy."
        # nginx allows one default_server per port, so theirs gives up the
        # flag. (Apache needs no edit: the catch-all is simply loaded first.)
        if [[ $WEB_SERVER == nginx ]] && grep -qE '^\s*listen\s+([^;]*:)?(80|443)[ ;].*default_server' "$file"; then
            WEB_BACKUPS+=("$file|$backup")
            sed -E -i '/^\s*listen\s+([^;]*:)?(80|443)[ ;]/ s/\s+default_server//' "$file"
            remember "$EDITED_SITES" "$file|$backup"
            CHANGED[web]=1
            note_change "$file: default_server moved to the bawls catch-all"
        fi
    done
}

decoy_domain_vars() {
    local first rest
    read -r first rest <<< "$DECOY_DOMAINS"
    V_DECOY_SERVER_NAME=$first
    V_DECOY_SERVER_NAMES=$DECOY_DOMAINS
    V_DECOY_SERVER_ALIAS=""
    [[ -z $rest ]] || V_DECOY_SERVER_ALIAS="    ServerAlias $rest"
    V_ACME_DIR="$STATE/acme"
    V_DECOY_CERT=/etc/letsencrypt/live/bawls-decoy/fullchain.pem
    V_DECOY_KEY=/etc/letsencrypt/live/bawls-decoy/privkey.pem
}

configure_web() {
    step "Web server ($WEB_SERVICE)"
    local mod restart=no
    if [[ $WEB_SERVER == apache ]]; then
        for mod in proxy proxy_http proxy_fcgi ssl headers rewrite setenvif; do
            [[ ! -e /etc/apache2/mods-enabled/$mod.load ]] || continue
            a2enmod -q "$mod" >/dev/null
            restart=yes
            CHANGED[web]=1
            note_change "apache module $mod"
        done
    fi
    systemctl enable --quiet --now "$PHP_FPM"

    self_signed console "$CONSOLE_HOST"
    self_signed default localhost

    # The console's allowlist, in each server's words.
    local require="" allow="" ip
    for ip in $CONSOLE_ALLOW 127.0.0.1; do
        require+="        Require ip $ip"$'\n'
        allow+="    allow $ip;"$'\n'
    done
    export V_MANAGED=$MANAGED V_INSTALL_DIR=$INSTALL_DIR V_PHP_FPM_SOCK=$PHP_FPM_SOCK \
        V_CONSOLE_HOST=$CONSOLE_HOST V_CONSOLE_CERT=/etc/ssl/bawls/console.crt \
        V_CONSOLE_KEY=/etc/ssl/bawls/console.key V_CONSOLE_REQUIRE="${require%$'\n'}" \
        V_CONSOLE_ALLOW_RULES="${allow}    deny all;" \
        V_INGEST_PORT=$INGEST_PORT V_DECOY_PORT=$DECOY_PORT \
        V_DEFAULT_CERT=/etc/ssl/bawls/default.crt V_DEFAULT_KEY=/etc/ssl/bawls/default.key
    local t=$WEB_SERVER sites=$SITES_AVAILABLE
    render "$t-console.conf.tmpl" "$sites/zz-bawls-console.conf" 0644 root web
    render "$t-ingest.conf.tmpl" "$sites/bawls-ingest.conf" 0644 root web
    enable_site zz-bawls-console.conf
    enable_site bawls-ingest.conf

    if [[ $DECOY_MODE != domain ]]; then
        claim_default_vhost
        render "$t-catchall.conf.tmpl" "$sites/000-bawls-catchall.conf" 0644 root web
        enable_site 000-bawls-catchall.conf
    else
        disable_site 000-bawls-catchall.conf
    fi

    if [[ $DECOY_MODE != catchall ]]; then
        decoy_domain_vars
        export V_DECOY_SERVER_NAME V_DECOY_SERVER_NAMES V_DECOY_SERVER_ALIAS V_ACME_DIR V_DECOY_CERT V_DECOY_KEY
        install -d -m 0755 "$V_ACME_DIR/.well-known/acme-challenge"
        local conf="$WORK/decoy-domain.conf"
        py render "$SRC_DIR/deploy/templates/$t-decoy-domain.conf.tmpl" > "$conf"
        if [[ -f $V_DECOY_CERT ]]; then
            py render "$SRC_DIR/deploy/templates/$t-decoy-domain-tls.conf.tmpl" >> "$conf"
        fi
        install_file "$conf" "$sites/bawls-decoy.conf" 0644 root web
        enable_site bawls-decoy.conf
    else
        disable_site bawls-decoy.conf
    fi

    [[ -n ${CHANGED[web]:-} ]] || { say "  ok: unchanged"; return 0; }

    local test_output
    if ! test_output="$(web_configtest)"; then
        rollback_web
        die "$WEB_SERVICE rejected the new config, so it was rolled back and not reloaded:
$test_output"
    fi
    if [[ "$(default_site_file 443)" == "$sites/zz-bawls-console.conf" ]]; then
        rollback_web
        die "the console would be the default HTTPS site, so anyone connecting to the
bare IP would see its certificate (and its private hostname). Rolled back.
Use DECOY_MODE=both, or give the server a default HTTPS site first."
    fi
    if [[ $DECOY_MODE != domain ]]; then
        local port
        for port in 80 443; do
            if [[ "$(default_site_file "$port")" != "$sites/000-bawls-catchall.conf" ]]; then
                rollback_web
                die "the decoy didn't become the default site on port $port (see apache2ctl -S
or nginx -T for what is). Rolled back."
            fi
        done
    fi
    if [[ $restart == yes ]]; then
        systemctl restart "$WEB_SERVICE"
    else
        systemctl reload "$WEB_SERVICE"
    fi
    say "  $WEB_SERVICE reloaded"
}

# Earlier versions had the web server log every decoy request too: a second
# copy of visitors' addresses and requests, unmasked and kept past bawls' own
# retention. The decoy vhosts no longer log; this removes what was written.
drop_decoy_access_logs() {
    local log removed=0
    for log in /var/log/apache2/bawls_decoy_access.log* /var/log/apache2/bawls_default_access.log* \
               /var/log/nginx/bawls_decoy_access.log* /var/log/nginx/bawls_default_access.log*; do
        [[ -f $log && ! -L $log ]] || continue
        rm -f "$log"
        removed=$((removed + 1))
    done
    [[ $removed -eq 0 ]] || note_change "removed $removed old decoy access log file(s)"
}

# cert_covers CERT DOMAIN...: the certificate names every one of the domains.
cert_covers() {
    local cert=$1 names domain
    shift
    names="$(openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' | sed -n 's/^ *DNS://p')"
    for domain in "$@"; do
        grep -qxF "$domain" <<< "$names" || return 1
    done
}

# letsencrypt: get the decoy domains' certificate, or widen it when a domain
# was added to DECOY_DOMAINS since (certbot renews it on its own after that).
letsencrypt() {
    [[ $LETSENCRYPT == yes ]] || return 0
    local cert=/etc/letsencrypt/live/bawls-decoy/fullchain.pem had_cert=no args=() domain domains
    read -ra domains <<< "$DECOY_DOMAINS"
    if [[ -f $cert ]]; then
        ! cert_covers "$cert" "${domains[@]}" || return 0
        had_cert=yes
        args+=(--expand)
    fi
    step "Let's Encrypt"
    for domain in "${domains[@]}"; do args+=(-d "$domain"); done
    # The email is optional: Let's Encrypt no longer sends expiry warnings.
    if [[ -n $LETSENCRYPT_EMAIL ]]; then args+=(-m "$LETSENCRYPT_EMAIL"); else args+=(--register-unsafely-without-email); fi
    if certbot certonly --webroot -w "$STATE/acme" --cert-name bawls-decoy "${args[@]}" \
        --non-interactive --agree-tos \
        --deploy-hook "systemctl reload $WEB_SERVICE"; then
        note_change "Let's Encrypt certificate for $DECOY_DOMAINS"
        # A first certificate switches the decoy domains' site to HTTPS, so the
        # web config is rendered again with it. A widened one is picked up by
        # certbot's reload: the site already names every domain.
        [[ $had_cert == no ]] || return 0
        CHANGED[web]=""
        WEB_BACKUPS=() WEB_ENABLED=() WEB_DISABLED=()
        configure_web
    else
        if [[ $had_cert == yes ]]; then
            warn "certbot couldn't add the new domain(s): the existing certificate stays, and doesn't cover them yet. Check that they point at this server, then re-run."
        else
            warn "certbot failed: the decoy domains are served over plain HTTP. Check that they point at this server, then re-run."
        fi
    fi
}

# ---------------------------------------------------------------- services

configure_services() {
    step "Services"
    install -d -m 0755 "$ETC"
    export V_MANAGED=$MANAGED V_INSTALL_DIR=$INSTALL_DIR V_INSTALL_PARENT=$INSTALL_PARENT \
        V_PYTHON=$PYTHON V_PHP_BIN=$PHP_BIN V_APP_USER=$APP_USER V_APP_GROUP=$APP_GROUP \
        V_THEME_DIR=$THEME_DIR V_THEME_BIND=$THEME_BIND V_DECOY_PORT=$DECOY_PORT \
        V_INGEST_PORT=$INGEST_PORT

    sensor_token V_DECOY_TOKEN "$HOST_SHORT-decoy" honeypot "$ETC/decoy.env"
    export V_DECOY_TOKEN
    render decoy.env.tmpl "$ETC/decoy.env" 0600 root decoy
    # A token is exported only while its env file is rendered, so the commands
    # run later as other users (the theme check, artisan) don't inherit it.
    export -n V_DECOY_TOKEN
    render bawls-decoy.service.tmpl /etc/systemd/system/bawls-decoy.service 0644 root decoy
    render bawls-scheduler.service.tmpl /etc/systemd/system/bawls-scheduler.service 0644 root sched
    if [[ $UFW_ON == yes ]]; then
        sensor_token V_UFW_TOKEN "$HOST_SHORT-ufw" ufw "$ETC/sensor.env"
        export V_UFW_TOKEN
        render sensor.env.tmpl "$ETC/sensor.env" 0600 root ufw
        export -n V_UFW_TOKEN
        render bawls-ufw-sensor.service.tmpl /etc/systemd/system/bawls-ufw-sensor.service 0644 root ufw
    else
        remove_unit bawls-ufw-sensor "UFW_SENSOR is off, or UFW isn't active" "$ETC/sensor.env"
    fi
    configure_site_sensor

    # Check the theme as the decoy user before (re)starting it, for a clear error.
    local theme_error
    if ! theme_error="$(cd "$INSTALL_DIR/sensors" && runuser -u bawls-decoy -- "$PYTHON" -I -c '
import sys
sys.path.insert(0, ".")
from pathlib import Path
import decoy_sensor
try:
    decoy_sensor.load_theme(Path(sys.argv[1]))
except (OSError, ValueError, KeyError) as error:
    sys.exit(str(error))' "$THEME_DIR" 2>&1)"; then
        die "the decoy can't use theme $THEME_DIR: $theme_error"
    fi

    if [[ -n ${CHANGED[decoy]:-}${CHANGED[sched]:-}${CHANGED[ufw]:-}${CHANGED[sites]:-} ]]; then
        systemctl daemon-reload
    fi
    # A graceful reload: in-flight requests finish, other sites are unaffected.
    [[ -z ${CHANGED[code]:-}${CHANGED[env]:-} ]] || systemctl reload "$PHP_FPM"
    local unit flag
    for unit in "${UNITS[@]}"; do
        unit_wanted "$unit" || continue
        flag=${UNIT_TAG[$unit]}
        systemctl is-enabled --quiet "$unit" 2>/dev/null || systemctl enable --quiet "$unit"
        if ! systemctl is-active --quiet "$unit"; then
            systemctl start "$unit"
            note_change "$unit started"
        elif [[ -n ${CHANGED[$flag]:-}${CHANGED[code]:-} || ( $unit == bawls-scheduler && -n ${CHANGED[env]:-} ) ]]; then
            # The scheduler (and the commands it starts) read .env; the decoy
            # and the sensors don't.
            systemctl restart "$unit"
            note_change "$unit restarted"
        fi
    done
}

# configure_site_sensor: the sensor that follows your real sites' access logs
# (SITE_LOGS) and sends their exploit attempts in, or its removal when the
# list is emptied.
configure_site_sensor() {
    if [[ $SITE_ON == no ]]; then
        remove_unit bawls-site-sensor "SITE_LOGS is empty" "$ETC/site-sensor.env"
        return 0
    fi
    local pair dirs=() dir
    for pair in $SITE_LOGS; do
        [[ -e ${pair#*=} ]] || warn "SITE_LOGS: ${pair#*=} doesn't exist yet; the sensor waits for it"
        dirs+=("$(dirname "${pair#*=}")")
    done
    V_SITE_LOG_BINDS="$(printf '%s\n' "${dirs[@]}" | sort -u | sed 's/^/BindReadOnlyPaths=-/')"
    V_SITE_LOGS=$SITE_LOGS
    V_SITE_SERVER_IP=${SERVER_IPS4[0]:-127.0.0.1}
    sensor_token V_SITE_TOKEN "$HOST_SHORT-sites" sites "$ETC/site-sensor.env"
    export V_SITE_LOG_BINDS V_SITE_LOGS V_SITE_SERVER_IP V_SITE_TOKEN
    render site-sensor.env.tmpl "$ETC/site-sensor.env" 0600 root sites
    export -n V_SITE_TOKEN
    render bawls-site-sensor.service.tmpl /etc/systemd/system/bawls-site-sensor.service 0644 root sites
}

# site_log_hint: with SITE_LOGS empty, name the other sites' logs it could watch.
site_log_hint() {
    local logs
    # No other sites is normal: an empty result must not stop the installer.
    if [[ $WEB_SERVICE == apache2 ]]; then
        logs="$(grep -hsoE '^\s*CustomLog\s+\S+' /etc/apache2/sites-enabled/* | awk '{ print $2 }' \
            | sed 's#\${APACHE_LOG_DIR}#/var/log/apache2#' | grep -v '/bawls_' | sort -u || true)"
    else
        logs="$(grep -hsoE '^\s*access_log\s+[^ ;]+' /etc/nginx/sites-enabled/* | awk '{ print $2 }' \
            | grep -v '/bawls_' | sort -u || true)"
    fi
    [[ -n $logs ]] || return 0
    say "  Your other sites' logs could ban exploit attempts too: set SITE_LOGS in $CONF to"
    say "  name=path pairs, from: $(paste -sd' ' <<< "$logs")"
}

configure_fail2ban() {
    local ban_log="$INSTALL_DIR/storage/logs/ban.log"
    export V_MANAGED=$MANAGED V_BAN_LOG=$ban_log V_APP_USER=$APP_USER V_APP_GROUP=$APP_GROUP
    if [[ $BAN == no ]]; then
        remove_fail2ban
        remove_ban_list
        return 0
    fi
    step "fail2ban"
    local allow never_block
    read -ra allow <<< "$CONSOLE_ALLOW"
    read -ra never_block <<< "$NEVER_BLOCK"
    local ignore=(127.0.0.1/8 ::1 "${SERVER_IPS4[@]}" "${SERVER_IPS6[@]}" "${allow[@]}" "${never_block[@]}")
    export V_BAN_TIME=$BAN_TIME
    V_IGNOREIP="$(printf '%s\n' "${ignore[@]}" | awk 'NF && !seen[$0]++' | paste -sd' ' -)"
    export V_IGNOREIP

    [[ -f $ban_log ]] || runuser -u "$APP_USER" -- touch "$ban_log"
    install_file "$SRC_DIR/deploy/fail2ban/filter.d/bawls.conf" /etc/fail2ban/filter.d/bawls.conf 0644 root f2b
    # BAN_TIME in seconds (fail2ban's units: s, m, h, d, w; a bare number is seconds), plus a day.
    local -A unit_seconds=([s]=1 [m]=60 [h]=3600 [d]=86400 [w]=604800)
    local ban_unit=${BAN_TIME//[0-9]/}
    V_PURGE_AGE=$(( ${BAN_TIME//[^0-9]/} * ${unit_seconds[${ban_unit:-s}]} + 86400 )) \
        render fail2ban-dbpurge.local.tmpl /etc/fail2ban/fail2ban.d/bawls.local 0644 root f2b

    # An IPv6 attacker is banned as a whole /64. fail2ban's iptables actions
    # take a range as they are; its nftables action needs a set made for
    # ranges, so where that is the server's "ban on every port" action, the
    # jail uses bawls' copy of it.
    local action_before action_file=/etc/fail2ban/action.d/bawls-nftables.conf default_action
    action_before="$(sed -n 's/^banaction *= *//p' /etc/fail2ban/jail.d/bawls.local 2>/dev/null || true)"
    # Later files override earlier ones, as fail2ban reads them; some may not exist.
    default_action="$({ sed -n 's/^banaction_allports *= *//p' /etc/fail2ban/jail.conf /etc/fail2ban/jail.d/*.conf \
        /etc/fail2ban/jail.local /etc/fail2ban/jail.d/*.local 2>/dev/null || true; } | tail -n1)"
    if [[ $default_action == nftables* ]]; then
        install_file "$SRC_DIR/deploy/fail2ban/action.d/bawls-nftables.conf" "$action_file" 0644 root f2b
        export V_BANACTION='bawls-nftables[type=allports]'
    else
        rm -f "$action_file"
        export V_BANACTION='%(banaction_allports)s'
    fi
    render fail2ban-jail.local.tmpl /etc/fail2ban/jail.d/bawls.local 0644 root f2b
    render logrotate-bawls-ban.tmpl /etc/logrotate.d/bawls-ban 0644 root logrotate

    if [[ -n ${CHANGED[f2b]:-} ]]; then
        local sample
        for sample in "bawls ban 203.0.113.9 rule=web_exploit alert=1" "bawls ban 2001:db8:1:2::/64 rule=web_exploit alert=2"; do
            [[ "$(fail2ban-regex "2026-01-01T00:00:00Z $sample" /etc/fail2ban/filter.d/bawls.conf 2>/dev/null)" == *"Lines: 1 lines, 0 ignored, 1 matched"* ]] \
                || die "the fail2ban filter doesn't match bawls ban lines ($sample)"
        done
    fi
    if ! systemctl is-active --quiet fail2ban; then
        systemctl enable --quiet --now fail2ban
        note_change "fail2ban started"
    elif [[ -n $action_before && $action_before != "$V_BANACTION" ]]; then
        # A jail's action can't be swapped by a reload (the jail is left with
        # none). A restart puts every jail's bans back from fail2ban's database.
        systemctl restart fail2ban
        note_change "fail2ban restarted (the bawls jail's ban action changed; bans are restored)"
    elif [[ -n ${CHANGED[f2b]:-} ]]; then
        fail2ban-client reload >/dev/null
        note_change "fail2ban reloaded"
    fi

    # The console's Lists page shows the bans, but only root can ask fail2ban:
    # a root timer copies them to a file the web group can read.
    export V_BAN_EXPORT=$BAN_EXPORT
    render bawls-bans.service.tmpl /etc/systemd/system/bawls-bans.service 0644 root bans
    render bawls-bans.timer.tmpl /etc/systemd/system/bawls-bans.timer 0644 root bans
    [[ -z ${CHANGED[bans]:-} ]] || systemctl daemon-reload
    systemctl is-enabled --quiet bawls-bans.timer 2>/dev/null || systemctl enable --quiet bawls-bans.timer
    if ! systemctl is-active --quiet bawls-bans.timer; then
        systemctl start bawls-bans.timer
        note_change "bawls-bans.timer started"
    elif [[ -n ${CHANGED[bans]:-} ]]; then
        systemctl restart bawls-bans.timer
    fi
    systemctl start bawls-bans.service  # a fresh copy now, not in a minute
    [[ -n ${CHANGED[f2b]:-}${CHANGED[bans]:-} ]] || say "  ok: unchanged"
}

# remove_fail2ban: the jail, its filter, bawls' fail2ban settings and the ban
# log's rotation. Reloading without the jail stops it, which lifts its bans.
remove_fail2ban() {
    local file removed=no
    for file in /etc/fail2ban/jail.d/bawls.local /etc/fail2ban/filter.d/bawls.conf /etc/fail2ban/fail2ban.d/bawls.local \
                /etc/fail2ban/action.d/bawls-nftables.conf; do
        [[ -f $file ]] || continue
        rm -f "${file:?}"
        removed=yes
    done
    rm -f /etc/logrotate.d/bawls-ban
    [[ $removed == yes ]] || return 0
    ! systemctl is-active --quiet fail2ban || fail2ban-client reload >/dev/null
    note_change "fail2ban jail bawls removed (its bans are lifted)"
}

# remove_ban_list: the timer that copies fail2ban's bans for the console.
remove_ban_list() {
    [[ -f /etc/systemd/system/bawls-bans.timer || -f /etc/systemd/system/bawls-bans.service ]] || return 0
    systemctl disable --now --quiet bawls-bans.timer 2>/dev/null || true
    rm -f /etc/systemd/system/bawls-bans.timer /etc/systemd/system/bawls-bans.service
    systemctl daemon-reload
    rm -rf "${STATE:?}/bans"
    note_change "bawls-bans timer removed"
}

# ---------------------------------------------------------------- checks

check() {  # check LABEL COMMAND...: one pass/fail line
    local label=$1
    shift
    if "$@"; then say "  ok    $label"; else say "  FAIL  $label"; CHECK_FAILED=1; fi
}
http_code() { curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$@" || true; }
# The jail is running and has its ban action (a jail whose action was swapped
# by a reload is left with none, and would ban nothing).
jail_up() {
    fail2ban-client status bawls >/dev/null 2>&1 \
        && [[ "$(fail2ban-client get bawls actions 2>/dev/null)" != *"No actions"* ]]
}

health() {
    step "Checks"
    CHECK_FAILED=0
    local code slug unit units=() token
    for unit in "${UNITS[@]}"; do
        ! unit_wanted "$unit" || units+=("$unit")
    done
    units+=("$WEB_SERVICE" "$PHP_FPM")
    [[ $BAN == no ]] || units+=(fail2ban)
    for unit in "${units[@]}"; do
        check "$unit running" systemctl is-active --quiet "$unit"
    done

    local _
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        code="$(http_code "http://127.0.0.1:$DECOY_PORT/")"
        [[ $code == 200 ]] && break
        sleep 1
    done
    check "decoy answers on 127.0.0.1:$DECOY_PORT" test "$code" = 200

    token="$(kv_get "$ETC/decoy.env" TRIPWIRE_TOKEN)"
    code="$(http_code -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' \
        -H "Authorization: Bearer $token" -d '{"events":[]}' "http://127.0.0.1:$INGEST_PORT/api/ingest")"
    check "ingest accepts the decoy's token" test "$code" = 422

    slug="$(kv_get "$INSTALL_DIR/.env" BAWLS_LOGIN_PATH)"
    code="$(http_code -k --resolve "$CONSOLE_HOST:443:127.0.0.1" "https://$CONSOLE_HOST/$slug")"
    check "console sign-in page" test "$code" = 200

    if [[ $DECOY_MODE != domain ]]; then
        code="$(http_code -H 'Host: unknown.invalid' http://127.0.0.1/)"
        check "catch-all serves the decoy" test "$code" = 200
    fi
    [[ $BAN == no ]] || check "fail2ban jail bawls" jail_up
    [[ $BAN == no ]] || check "ban list for the console" mode_owner_is "$BAN_EXPORT" "640 root:$APP_GROUP"
    local site
    for site in $SITE_LOGS; do
        check "${site%%=*}'s ${site##*/} is readable by the site sensor" adm_can_read "${site#*=}"
    done
    return "$CHECK_FAILED"
}

mode_owner_is() {  # mode_owner_is FILE "MODE USER:GROUP"
    [[ -e $1 && "$(stat -c '%a %U:%G' "$1")" == "$2" ]]
}

sandbox_ok() {  # sandbox_ok UNIT: systemd's exposure score for it is 2.0 or lower
    local score
    score="$(systemd-analyze security "$1" 2>/dev/null | sed -n "s/.*exposure level for $1.service: \([0-9.]*\).*/\1/p")"
    [[ -n $score ]] && awk -v s="$score" 'BEGIN { exit !(s <= 2.0) }'
}

# adm_can_read FILE: the adm group (the site sensor's) can read it, directories included.
adm_can_read() { runuser -u nobody -g adm -- test -r "$1"; }

cert_ok() {  # cert_ok FILE DAYS: valid for at least DAYS more days
    openssl x509 -in "$1" -noout -checkend $(($2 * 86400)) >/dev/null 2>&1
}

# The health figures are read as the app's user: root opens nothing in a
# directory that user can write.
# Exploit attempts the site sensor recorded in the last 24 hours.
site_exploits_24h() {
    runuser -u "$APP_USER" -- python3 -I - "$INSTALL_DIR/database/database.sqlite" <<'PY'
import sqlite3, sys
db = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
print(db.execute("select count(*) from events where source = 'site_http' and occurred_at > datetime('now', '-1 day')").fetchone()[0])
PY
}

# Minutes since the decoy last recorded a visit, or "never".
minutes_since_last_decoy_event() {
    runuser -u "$APP_USER" -- python3 -I - "$INSTALL_DIR/database/database.sqlite" <<'PY'
import sqlite3, sys
from datetime import datetime, timezone
db = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
last = db.execute("select max(occurred_at) from events where source = 'honeypot_http'").fetchone()[0]
if not last:
    print("never")
else:
    when = datetime.fromisoformat(last).replace(tzinfo=timezone.utc)
    print(int((datetime.now(timezone.utc) - when).total_seconds() // 60))
PY
}

# --check: everything health() checks, plus file permissions, the decoy's
# sandbox, certificates and recent activity. Changes nothing.
doctor() {
    [[ -f $CONF && -f $INSTALL_DIR/artisan ]] || die "bawls isn't installed here (no $CONF or $INSTALL_DIR)"
    say "  bawls $(release_version "$INSTALL_DIR") in $INSTALL_DIR"
    resolve_web_server
    detect_runtime
    health || true
    local failed=$CHECK_FAILED

    step "Security"
    CHECK_FAILED=$failed
    check ".env is 640 root:$APP_GROUP" mode_owner_is "$INSTALL_DIR/.env" "640 root:$APP_GROUP"
    check "database is private to $APP_USER" mode_owner_is "$INSTALL_DIR/database" "770 $APP_USER:$APP_GROUP"
    check "decoy token is root-only" mode_owner_is "$ETC/decoy.env" "600 root:root"
    [[ $UFW_ON == no ]] || check "UFW sensor token is root-only" mode_owner_is "$ETC/sensor.env" "600 root:root"
    [[ $SITE_ON == no ]] || check "site sensor token is root-only" mode_owner_is "$ETC/site-sensor.env" "600 root:root"
    check "console login file is root-only" mode_owner_is "$CREDENTIALS" "600 root:root"
    check "decoy sandbox exposure 2.0 or lower" sandbox_ok bawls-decoy
    [[ $SITE_ON == no ]] || check "site sensor sandbox exposure 2.0 or lower" sandbox_ok bawls-site-sensor
    check "console certificate valid for 30+ days" cert_ok /etc/ssl/bawls/console.crt 30
    if [[ -f /etc/letsencrypt/live/bawls-decoy/fullchain.pem ]]; then
        check "decoy domain certificate valid for 14+ days" cert_ok /etc/letsencrypt/live/bawls-decoy/fullchain.pem 14
    fi

    step "Activity"
    local minutes
    minutes="$(minutes_since_last_decoy_event 2>/dev/null || echo unknown)"
    case $minutes in
        never) say "  info  the decoy hasn't recorded a visit yet" ;;
        unknown) say "  info  couldn't read the database" ;;
        *) if (( minutes > 1440 )); then
               say "  warn  no decoy visits for $((minutes / 60)) hours: is the decoy reachable from the internet?"
           else
               say "  info  last decoy visit $minutes minute(s) ago"
           fi ;;
    esac
    if [[ $BAN == yes ]] && jail_up; then
        say "  info  $(fail2ban-client status bawls | sed -n 's/.*Currently banned:\s*//p') IP(s) banned right now"
    fi
    if [[ $SITE_ON == yes ]]; then
        say "  info  $(site_exploits_24h 2>/dev/null || echo '?') exploit attempt(s) on your real sites in the last 24h$([[ $SITE_BAN == yes ]] || echo ' (watching: they don'"'"'t ban yet)')"
    fi
    say "  info  database $(du -h "$INSTALL_DIR/database/database.sqlite" | cut -f1)"

    step "Result"
    if [[ $CHECK_FAILED == 0 ]]; then
        say "  All checks passed."
    else
        say "  Some checks failed (above). Re-running install.sh repairs most of them."
        exit 1
    fi
}

confirm() {  # confirm PROMPT: --yes, or the word "yes" typed at a terminal
    [[ $ASSUME_YES == yes ]] && return 0
    [[ -t 0 ]] || die "$1 Re-run with --yes to confirm."
    local answer
    read -r -p "$1 Type yes to continue: " answer
    [[ $answer == yes ]] || die "cancelled; nothing was changed"
}

# For --uninstall: take bawls' sites out of whichever web server has them, and
# put back what bawls changed there (a stock default it disabled, an nginx
# default_server it moved).
remove_web_sites() {
    local server site who file backup touched
    for server in apache nginx; do
        WEB_SERVER=$server
        if [[ $server == apache ]]; then WEB_SERVICE=apache2; else WEB_SERVICE=nginx; fi
        SITES_AVAILABLE="/etc/$WEB_SERVICE/sites-available"
        SITES_ENABLED="/etc/$WEB_SERVICE/sites-enabled"
        web_installed || continue
        touched=no
        for site in 000-bawls-catchall.conf bawls-decoy.conf bawls-ingest.conf zz-bawls-console.conf; do
            [[ -f $SITES_AVAILABLE/$site ]] || continue
            if [[ -e $SITES_ENABLED/$site ]]; then
                if [[ $server == apache ]]; then a2dissite -q "$site" >/dev/null; else nginx_unlink "$site"; fi
            fi
            unlink "$SITES_AVAILABLE/$site"
            touched=yes
            note_change "$WEB_SERVICE site $site removed"
        done
        if [[ -f $DISABLED_SITES ]]; then
            while read -r who site; do
                [[ -n $site ]] || { site=$who; who=apache; }   # 0.1.0 wrote only the name
                [[ $who == "$server" ]] || continue
                [[ $server == nginx || $site == *.conf ]] || site="$site.conf"
                [[ -f $SITES_AVAILABLE/$site && ! -e $SITES_ENABLED/$site ]] || continue
                if [[ $server == apache ]]; then
                    a2ensite -q "$site" >/dev/null
                else
                    ln -s "$SITES_AVAILABLE/$site" "$SITES_ENABLED/$site"
                fi
                touched=yes
                note_change "$WEB_SERVICE site $site re-enabled"
            done < "$DISABLED_SITES"
        fi
        if [[ -f $EDITED_SITES ]]; then
            while IFS='|' read -r file backup; do
                [[ $file == /etc/$WEB_SERVICE/* && -f $backup && -f $file ]] || continue
                # Only if nobody has edited it since; otherwise say where the original is.
                if cmp -s "$file" <(sed -E '/^\s*listen\s+([^;]*:)?(80|443)[ ;]/ s/\s+default_server//' "$backup"); then
                    cp -p "$backup" "$file"
                    touched=yes
                    note_change "$file: default_server given back"
                else
                    warn "$file changed since bawls edited it; its original is $backup (kept)"
                fi
            done < "$EDITED_SITES"
        fi
        if [[ $touched == yes ]]; then
            if web_configtest >/dev/null; then
                ! systemctl is-active --quiet "$WEB_SERVICE" || systemctl reload "$WEB_SERVICE"
            else
                warn "$WEB_SERVICE's config doesn't pass its config test; not reloading it"
            fi
        fi
    done
    rm -f "${DISABLED_SITES:?}" "${EDITED_SITES:?}"
}

# --uninstall: remove the services, web server config, firewall jail and
# certificates. The app's data (database, .env, config, sensor tokens) stays
# unless --purge, so `sudo $INSTALL_DIR/install.sh` brings it all back.
uninstall() {
    read_config
    validate_config
    if [[ $PURGE == yes ]]; then
        confirm "This deletes $INSTALL_DIR (the database and every recorded event), $ETC, $STATE and $CREDENTIALS."
    fi
    step "Uninstall"
    local unit site
    for unit in "${UNITS[@]}"; do
        remove_unit "$unit" ""
    done
    remove_ban_list

    remove_web_sites

    remove_fail2ban
    if [[ -d /etc/ssl/bawls ]]; then
        rm -rf /etc/ssl/bawls
        note_change "/etc/ssl/bawls removed"
    fi
    if id bawls-decoy >/dev/null 2>&1; then
        userdel bawls-decoy
        note_change "user bawls-decoy removed"
    fi
    local pool
    for pool in /etc/php/*/fpm/pool.d/bawls.conf; do
        [[ -f $pool ]] || continue
        rm -f "$pool"
        systemctl reload "php$(cut -d/ -f4 <<< "$pool")-fpm" 2>/dev/null || true
        note_change "PHP-FPM pool bawls removed"
    done

    if [[ $PURGE == yes ]]; then
        if [[ -d $INSTALL_DIR ]]; then
            [[ -f $INSTALL_DIR/artisan && -f $INSTALL_DIR/sensors/decoy_sensor.py ]] \
                || die "$INSTALL_DIR doesn't look like a bawls install; not deleting it"
            rm -rf "${INSTALL_DIR:?}"
            note_change "$INSTALL_DIR deleted"
        fi
        if [[ -d /etc/letsencrypt/live/bawls-decoy ]] && command -v certbot >/dev/null; then
            certbot delete --cert-name bawls-decoy --non-interactive >/dev/null 2>&1 || true
            note_change "Let's Encrypt certificate bawls-decoy deleted"
        fi
        rm -rf "${ETC:?}" "${STATE:?}" /var/lib/bawls-ufw /var/lib/private/bawls-ufw \
            /var/lib/bawls-sites /var/lib/private/bawls-sites "${CREDENTIALS:?}"
        note_change "$ETC, $STATE and $CREDENTIALS deleted"
        # Only with --purge: without it the user still owns the data that was kept.
        if id "$APP_USER" >/dev/null 2>&1; then
            userdel "$APP_USER"
            note_change "user $APP_USER removed"
        fi
    fi

    step "Done"
    if [[ $PURGE == yes ]]; then
        say "  bawls is gone. Packages it installed (the web server, PHP, fail2ban) were left in place."
    else
        say "  bawls is off. Kept: $INSTALL_DIR (database, .env), $ETC (config, sensor tokens)"
        say "  and $CREDENTIALS. Bring it back with: sudo $INSTALL_DIR/install.sh"
        say "  Delete everything with: sudo $INSTALL_DIR/install.sh --uninstall --purge"
    fi
}

summary() {
    step "Done"
    if [[ ${#CHANGES[@]} -eq 0 ]]; then
        say "  Nothing to change: this server already matches $CONF."
    else
        say "  ${#CHANGES[@]} change(s) made."
    fi
    say "  Console: https://$CONSOLE_HOST/ (sign-in path and password: sudo cat $CREDENTIALS)"
    say "  Hosts-file line for your computer:  ${SERVER_IP:-<server IP>}  $CONSOLE_HOST"
    say "  Console allowed from: $CONSOLE_ALLOW"
    case $DECOY_MODE in
        catchall) say "  Decoy: the catch-all (bare IP and unknown hosts)" ;;
        domain) say "  Decoy: $DECOY_DOMAINS" ;;
        both) say "  Decoy: $DECOY_DOMAINS, and the catch-all" ;;
    esac
    [[ $BAN == no ]] || say "  Bans: $BAN_TIME on every port for exploit attempts (sudo fail2ban-client status bawls)"
    if [[ $SITE_ON == yes ]]; then
        # A site with several logs (http and https) is named once.
        say "  Your sites' logs: $(for s in $SITE_LOGS; do printf '%s\n' "${s%%=*}"; done | awk '!seen[$0]++' | paste -sd' ' -) ($([[ $SITE_BAN == yes ]] && echo 'exploit attempts ban, like the decoy' || echo 'watching: recorded and alerted, no bans yet'))"
    else
        site_log_hint
    fi
    [[ -z $BACKUP_DIR ]] || say "  Backup of the previous version: $BACKUP_DIR"
    return 0
}

install_all() {
    step "Config"
    settle_config
    preflight
    install_packages
    detect_runtime
    install_code
    write_env
    console_user
    configure_web
    letsencrypt
    drop_decoy_access_logs
    configure_services
    configure_fail2ban
    health || die "some checks failed (above). Logs: journalctl -u bawls-decoy -u bawls-scheduler, /var/log/$WEB_SERVICE/"
    summary
}

main() {
    parse_args "$@"
    [[ $EUID -eq 0 ]] || die "run as root: sudo $0 $*"
    case $MODE in
        install) install_all ;;
        check) step "bawls health check"; read_config; validate_config; doctor ;;
        uninstall) uninstall ;;
    esac
}

main "$@"
