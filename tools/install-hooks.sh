#!/bin/sh
# Install TelcoLadder's git hooks into this clone.
#
# Hooks live in tools/hooks/ (version controlled) and are copied into
# .git/hooks/ (not version controlled, which is why this script exists).
#
# We copy rather than setting core.hooksPath because other tools install their
# own hooks into .git/hooks/ — pointing hooksPath elsewhere would silently
# disable them. Copying keeps everyone's hooks working; the cost is re-running
# this script if tools/hooks/ changes.
#
# Existing hooks are never overwritten blindly: a hook we did not write is
# moved to <name>.local and chained, so it still runs first.

set -eu

cd "$(dirname "$0")/.."
SRC=tools/hooks
DST=$(git rev-parse --git-path hooks)
MARKER='telcoladder-hook:'

[ -d "$SRC" ] || { echo "no $SRC directory — are you in the repo root?" >&2; exit 1; }
mkdir -p "$DST"

for src in "$SRC"/*; do
    [ -f "$src" ] || continue
    name=$(basename "$src")
    dst="$DST/$name"

    if [ -e "$dst" ] && ! grep -q "$MARKER" "$dst" 2>/dev/null; then
        # Someone else's hook. Keep it, and chain to it from ours.
        if [ ! -e "$dst.local" ]; then
            mv "$dst" "$dst.local"
            chmod +x "$dst.local"
            echo "  kept existing $name as $name.local (it will still run)"
        else
            echo "  ! $name.local already exists; leaving $name alone" >&2
            continue
        fi
    fi

    cp "$src" "$dst"
    chmod +x "$dst"

    # If we displaced someone's hook, run theirs first.
    if [ -e "$dst.local" ]; then
        tmp=$(mktemp)
        {
            head -1 "$dst"
            printf '\n_local="$(git rev-parse --git-path hooks)/%s.local"\n' "$name"
            printf '[ -x "$_local" ] && { "$_local" "$@" || exit $?; }\n\n'
            tail -n +2 "$dst"
        } > "$tmp"
        mv "$tmp" "$dst"
        chmod +x "$dst"
    fi

    echo "  installed $name"
done

echo
echo "Done. The pre-commit hook runs tests/test_no_real_subscriber_data.py"
echo "(about 0.2s) and refuses commits that carry real subscriber or customer"
echo "data. Bypass once with: git commit --no-verify"
