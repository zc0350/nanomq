#!/bin/sh
# Maintain the NanoNNG build-time patches in cong/patch/.
#
# The nng submodule is pinned by this repository and cannot carry local
# commits, so every change to it lives as a patch that CI applies to the
# pristine pin before configuring the build. This script keeps those patches
# and the local nng worktree from drifting apart.
#
#   nng-patches.sh verify
#       Clone the pinned submodule commit into a scratch directory, apply
#       every patch in cong/patch/ in file-name order (--check first), then
#       reverse them in reverse order and require a clean tree. Fails loudly
#       as soon as a patch no longer matches the pin.
#
#   nng-patches.sh export <name> <path> [<path>...]
#       Regenerate cong/patch/<name>.patch from the local nng worktree. The
#       paths must be touched by that patch and no other one: earlier patches
#       are replayed on top of the pin by CI, and later patches would leak
#       their own changes into the regenerated file. Run `verify` afterwards.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
PATCH_DIR="$ROOT/cong/patch"
NNG_DIR="$ROOT/nng"
PIN=$(git -C "$ROOT" ls-tree HEAD -- nng | awk '{print $3}')

usage() {
	echo "usage: $0 verify" >&2
	echo "       $0 export <name> <path> [<path>...]" >&2
	exit 2
}

verify() {
	[ -n "$PIN" ] || { echo "cannot resolve the nng submodule pin" >&2; exit 1; }
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT INT TERM
	git clone -q --no-checkout "$NNG_DIR" "$tmp/nng"
	# normalize line endings before the checkout: the patches are LF, and a
	# CRLF worktree would make every hunk fail
	git -C "$tmp/nng" config core.autocrlf false
	git -C "$tmp/nng" checkout -q "$PIN"

	for p in "$PATCH_DIR"/*.patch; do
		echo "apply   $(basename "$p")"
		git -C "$tmp/nng" apply --check "$p"
		git -C "$tmp/nng" apply "$p"
	done

	reverse=""
	for p in "$PATCH_DIR"/*.patch; do
		reverse="$p $reverse"
	done
	for p in $reverse; do
		echo "reverse $(basename "$p")"
		git -C "$tmp/nng" apply -R --check "$p"
		git -C "$tmp/nng" apply -R "$p"
	done

	if [ -n "$(git -C "$tmp/nng" status --porcelain)" ]; then
		echo "error: the nng tree is not clean after reversing every patch" >&2
		exit 1
	fi
	echo "ok: all patches apply and reverse cleanly against $PIN"
}

export_patch() {
	[ $# -ge 2 ] || usage
	name=$1
	shift
	[ -f "$PATCH_DIR/$name.patch" ] ||
		echo "note: $PATCH_DIR/$name.patch does not exist yet, creating it"

	for p in "$PATCH_DIR"/*.patch; do
		[ "$(basename "$p" .patch)" = "$name" ] && continue
		for path in "$@"; do
			if grep -q -- "^+++ b/$path\$" "$p"; then
				echo "error: $path is already touched by $(basename "$p")" >&2
				echo "       only a patch no other patch overlaps can be exported" >&2
				exit 1
			fi
		done
	done

	git -C "$NNG_DIR" diff HEAD -- "$@" > "$PATCH_DIR/$name.patch"
	if [ ! -s "$PATCH_DIR/$name.patch" ]; then
		rm -f "$PATCH_DIR/$name.patch"
		echo "error: the worktree has no changes in: $*" >&2
		exit 1
	fi
	echo "wrote $PATCH_DIR/$name.patch:"
	git -C "$NNG_DIR" diff --stat HEAD -- "$@"
	echo "now run: $0 verify"
}

case "${1:-}" in
verify) verify ;;
export) shift; export_patch "$@" ;;
*) usage ;;
esac
