#!/usr/bin/env bash
# Build a bawls release: the source tree plus production vendor/ and the
# compiled front end (public/build), so servers need neither Composer nor
# Node. Writes dist/bawls-<version>.tar.gz and its .sha256.
#
#   deploy/build-release.sh
#
# The tree is taken from git: every tracked or new file that isn't ignored,
# as it is on disk. A tree with uncommitted changes gets a "-dirty" version,
# fine for testing, never for a real release.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

for tool in git composer npm tar sha256sum; do
    command -v "$tool" >/dev/null || { echo "build-release: $tool is required" >&2; exit 1; }
done

version="$(git describe --tags --always --dirty)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "Building bawls ${version}"
mkdir "$work/bawls"
git ls-files -z --cached --others --exclude-standard \
    | while IFS= read -r -d '' path; do [[ -e $path ]] && printf '%s\0' "$path"; done \
    | tar --null -T - -cf - | tar -xf - -C "$work/bawls"
# Development-only files have no place on a server.
(cd "$work/bawls" && rm -rf .github .claude docs tests phpunit.xml AGENTS.md CLAUDE.md boost.json sensors/test_*.py)

(
    cd "$work/bawls"
    # --no-scripts: package:discover would boot the app, which refuses to run
    # without a sign-in slug. Laravel builds that cache on the server instead.
    composer install --no-dev --optimize-autoloader --no-scripts --no-interaction --no-progress --quiet
    rm -f bootstrap/cache/*.php
    npm ci --no-audit --no-fund --silent
    npm run build --silent >/dev/null
    rm -rf node_modules
    printf '%s\n' "$version" > VERSION
)

[[ -f $work/bawls/vendor/autoload.php && -f $work/bawls/public/build/manifest.json ]] \
    || { echo "build-release: vendor/ or public/build is missing" >&2; exit 1; }

mkdir -p dist
tarball="dist/bawls-${version}.tar.gz"
tar -C "$work" --owner=0 --group=0 --numeric-owner --mode='u+rwX,go+rX,go-w' -czf "$tarball" bawls
(cd dist && sha256sum "$(basename "$tarball")" > "$(basename "$tarball").sha256")

echo "$tarball ($(du -h "$tarball" | cut -f1))"
