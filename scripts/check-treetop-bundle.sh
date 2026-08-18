#!/bin/sh

set -eu

bundle_bin=${TREETOP_BUNDLE_BIN:-treetop-bundle}
manifest=${TREETOP_BUNDLE_MANIFEST:-treetop/data/treetop-bundle.toml}
archive=${TREETOP_BUNDLE_ARCHIVE:-treetop/data/mreg-bundle.tar.gz}

if ! command -v "$bundle_bin" >/dev/null 2>&1; then
    echo "treetop-bundle executable not found: $bundle_bin" >&2
    exit 127
fi

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/mreg-treetop-bundle.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM
generated_archive="$tmpdir/mreg-bundle.tar.gz"

"$bundle_bin" check bundle "$manifest" --format human
"$bundle_bin" build \
    --manifest "$manifest" \
    --output "$generated_archive" \
    --format human
"$bundle_bin" check archive "$generated_archive" \
    --signature-policy allow-unsigned \
    --format human

if ! cmp -s "$generated_archive" "$archive"; then
    echo "Committed TreeTop bundle is stale. Rebuild it with treetop-bundle." >&2
    exit 1
fi

echo "TreeTop bundle is valid, unsigned, and reproducible."
