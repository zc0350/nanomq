#!/bin/sh
# Build the Debian package for one architecture out of a staged release tree.
#
# The release pipeline stages the tarball layout into pack/<name>/, then calls
# this script: the same two binaries are laid out the way a Debian package
# should be and dpkg-deb wraps them. Nothing here needs debhelper, extra
# build-deps or the network, so the package is built on the runner that
# already built the broker.
#
#   sh cong/tools/build-deb.sh --stage <dir> --version <ver> --arch <arch> \
#                              --out <dir>
#
#     --stage    tarball tree with nanomq and cong_nanomq.so in it
#     --version  package version; '_' becomes '+' because dpkg rejects '_'
#                outright and the pipeline uses it to carry the git hash
#     --arch     dpkg architecture name (amd64 / arm64)
#     --out      directory for nanomq-cong_<version>_<arch>.deb (+ .sha256)
#
# Prints the path of the .deb. It fails loudly on anything it cannot lay out
# correctly: a drifted path in the unit or the conf, a staged lib/ directory
# (the release binaries link mbedTLS statically), or a binary that needs a
# shared library the control file does not depend on.
set -eu

die() { echo "build-deb: $*" >&2; exit 1; }

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
STAGE= VERSION= ARCH= OUT=
while [ $# -gt 0 ]; do
    case "$1" in
        --stage)   STAGE=${2?};   shift 2 ;;
        --version) VERSION=${2?}; shift 2 ;;
        --arch)    ARCH=${2?};    shift 2 ;;
        --out)     OUT=${2?};     shift 2 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[ -n "$STAGE" ] && [ -n "$VERSION" ] && [ -n "$ARCH" ] && [ -n "$OUT" ] ||
    die "usage: build-deb.sh --stage <dir> --version <ver> --arch <arch> --out <dir>"

[ -f "$STAGE/nanomq" ]         || die "$STAGE/nanomq is missing"
[ -f "$STAGE/cong_nanomq.so" ] || die "$STAGE/cong_nanomq.so is missing"

# dpkg's version syntax: a digit first, then alphanumerics and . + ~ -
# ('-' separates upstream from the revision, so 0.25.7-cong.3 is upstream
# 0.25.7, revision cong.3). Master builds are named 0.25.7_<gitsha>, which
# dpkg would reject, hence the rewrite.
VERSION=$(printf '%s' "$VERSION" | tr '_' '+')
printf '%s' "$VERSION" | grep -qE '^[0-9][0-9A-Za-z.+~-]*$' ||
    die "not a usable dpkg version: $VERSION"
case "$VERSION" in *-) die "version must not end with '-': $VERSION" ;; esac

# Bundled shared libraries would need an ld.so.conf.d entry plus an ldconfig
# hook, which this packager does not have. The release binaries need none
# (nanomq links mbedTLS statically, the plugin uses the system libcrypto), so
# refuse rather than ship a package that cannot find its libraries.
if [ -d "$STAGE/lib" ] && [ -n "$(ls -A "$STAGE/lib" 2>/dev/null)" ]; then
    die "$STAGE/lib is not empty - bundled libraries are not handled here"
fi

# What the two binaries need at runtime, and what the control file promises.
# Keep them in step: a new dependency must be added to Depends by hand, and
# the check below refuses to build until it is.
ALLOWED_LIBS="libc.so.6 libcrypto.so.3"   # -> libc6, libssl3t64
GLIBC_MIN=2.38                            # Ubuntu 24.04, the oldest runner used

needed=$(for bin in nanomq cong_nanomq.so; do
             readelf -d "$STAGE/$bin" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p'
         done | LC_ALL=C sort -u)
for lib in $needed; do
    case " $ALLOWED_LIBS " in
        *" $lib "*) continue ;;
    esac
    # aarch64 executables list the dynamic loader itself; it ships in libc6,
    # like libc.so.6 does, so any architecture's loader is covered
    case "$lib" in ld-linux-*.so.*) continue ;; esac
    die "$lib is needed at runtime but not in Depends"
done

required=$(objdump -T "$STAGE/nanomq" "$STAGE/cong_nanomq.so" |
    grep -o 'GLIBC_[0-9.]*' | LC_ALL=C sort -Vu | tail -n 1 | sed 's/^GLIBC_//')
[ -n "$required" ] || die "cannot read the required glibc version"
[ "$(printf '%s\n%s\n' "$GLIBC_MIN" "$required" | LC_ALL=C sort -V | tail -n 1)" = \
    "$GLIBC_MIN" ] ||
    die "binaries need glibc $required but Depends says >= $GLIBC_MIN"

PKG=nanomq-cong
WORK="$OUT/.$PKG-$ARCH.build"
D="$WORK/$PKG"
rm -rf "$WORK"
mkdir -p "$D/DEBIAN" "$D/usr/bin" "$D/usr/lib/nanomq" "$D/usr/lib/systemd/system" \
    "$D/usr/share/doc/nanomq-cong/examples" "$D/etc/nanomq"
trap 'rm -rf "$WORK"' EXIT INT TERM

install -m 0755 "$STAGE/nanomq"         "$D/usr/bin/nanomq"
install -m 0755 "$STAGE/cong_nanomq.so" "$D/usr/lib/nanomq/cong_nanomq.so"

# The unit and the conf are the files the tarball ships with the /usr/local
# paths rewritten. Keeping one copy of each in the repo means the two layouts
# cannot drift, and the greps fail the build if a rewrite stops matching.
sed -e 's|^ExecStart=/usr/local/sbin/nanomq |ExecStart=/usr/bin/nanomq |' \
    -e 's|^Documentation=file:///usr/local/share/doc/cong-nanomq/README.md$|Documentation=file:///usr/share/doc/nanomq-cong/README.md|' \
    "$ROOT/cong/deploy/nanomq.service" > "$D/usr/lib/systemd/system/nanomq.service"
grep -q '^ExecStart=/usr/bin/nanomq ' "$D/usr/lib/systemd/system/nanomq.service" ||
    die "unit ExecStart rewrite did not match - cong/deploy/nanomq.service changed"
grep -q '^Documentation=file:///usr/share/doc/nanomq-cong/README.md$' \
    "$D/usr/lib/systemd/system/nanomq.service" ||
    die "unit Documentation rewrite did not match - cong/deploy/nanomq.service changed"

sed -e 's|path = "/usr/local/lib/cong_nanomq.so"|path = "/usr/lib/nanomq/cong_nanomq.so"|' \
    "$ROOT/cong/conf/nanomq.conf" > "$D/etc/nanomq/nanomq.conf"
grep -q 'path = "/usr/lib/nanomq/cong_nanomq.so"' "$D/etc/nanomq/nanomq.conf" ||
    die "plugin path rewrite did not match - cong/conf/nanomq.conf changed"

install -m 0644 "$ROOT/cong/README.md" "$D/usr/share/doc/nanomq-cong/README.md"
install -m 0644 "$ROOT/LICENSE.txt"    "$D/usr/share/doc/nanomq-cong/copyright"
install -m 0644 "$ROOT/cong/rules/auth.jsonl" \
    "$D/usr/share/doc/nanomq-cong/examples/auth.jsonl"
install -m 0644 "$ROOT/cong/rules/acl.jsonl" \
    "$D/usr/share/doc/nanomq-cong/examples/acl.jsonl"

install -m 0755 "$ROOT/cong/deploy/deb/postinst" "$D/DEBIAN/postinst"
install -m 0755 "$ROOT/cong/deploy/deb/prerm"    "$D/DEBIAN/prerm"
install -m 0755 "$ROOT/cong/deploy/deb/postrm"   "$D/DEBIAN/postrm"
printf '/etc/nanomq/nanomq.conf\n' > "$D/DEBIAN/conffiles"

# dpkg --verify reads md5sums; conffiles are excluded, as dh_md5sums does.
( cd "$D" && find . -type f ! -path './DEBIAN/*' ! -path './etc/*' |
    sed 's|^\./||' | LC_ALL=C sort | xargs -r md5sum > DEBIAN/md5sums )

size=$(du -ks "$D" | cut -f1)
cat > "$D/DEBIAN/control" <<EOF
Package: $PKG
Version: $VERSION
Architecture: $ARCH
Maintainer: zc0350 <zc0350@users.noreply.github.com>
Installed-Size: $size
Depends: libc6 (>= $GLIBC_MIN), libssl3t64
Section: net
Priority: optional
Homepage: https://github.com/zc0350/nanomq
Description: NanoMQ MQTT broker with the cong JSONL login + ACL plugin
 NanoMQ (NanoNNG) built with the plugin framework, the ACL support and the
 cong plugin, which owns CONNECT authentication and topic authorisation.
 .
 Login and ACL rules live in /etc/nanomq/cong_auth.jsonl and
 /etc/nanomq/cong_acl.jsonl, read through the CONG_AUTH_FILE / CONG_ACL_FILE
 environment variables set in the systemd unit - the broker config cannot
 pass options to a plugin.
 .
 No rule files are shipped: without them the plugin denies every connection.
 Copy the examples from /usr/share/doc/nanomq-cong/examples/ and edit them,
 then enable the unit (it is installed but not enabled, see the postinst
 message). Derive password digests with cong/tools/cong_pwgen.py.
EOF

DEB="$OUT/${PKG}_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$D" "$DEB" >/dev/null

# Same convention as the tarball: a bare file name inside the .sha256, so
# sha256sum -c works in whatever directory the release assets land in.
( cd "$OUT" && sha256sum "$(basename "$DEB")" > "$(basename "$DEB").sha256" )

dpkg-deb --info "$DEB" >&2
dpkg-deb --contents "$DEB" >&2
printf '%s\n' "$DEB"
