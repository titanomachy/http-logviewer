#!/usr/bin/env bash
# Exercise real shell command lookup without changing the user's bin directory.
# Child shells intentionally expand these expressions themselves.
# shellcheck disable=SC2016
set -euo pipefail

HLV_INSTALLER=$(cd "$(dirname "$0")/../scripts" && pwd)/install_hlv.sh
hlv_test_dir=$(mktemp -d)
trap 'rm -rf "$hlv_test_dir"' EXIT
mkdir "$hlv_test_dir/tools"
for hlv_tool in basename dirname mkdir ln cat; do
    ln -s "$(command -v "$hlv_tool")" "$hlv_test_dir/tools/$hlv_tool"
done

run_test_shell() {
    # Isolate PATH and exported shell functions so an actual user-installed hlv
    # cannot influence these tests.
    env -i PATH="$hlv_test_dir/tools" HLV_INSTALLER="$HLV_INSTALLER" \
        HLV_BINARY="$HLV_BINARY" HLV_BIN="$HLV_BIN" HLV_OTHER="$HLV_OTHER" \
        "$hlv_shell" "$@"
}

for hlv_shell in bash zsh; do
    command -v "$hlv_shell" >/dev/null || continue
    hlv_shell=$(command -v "$hlv_shell")
    HLV_BIN=$hlv_test_dir/"$(basename "$hlv_shell")"/bin
    HLV_BINARY=$hlv_test_dir/'viewer with spaces'
    HLV_OTHER=$hlv_test_dir/other
    mkdir -p "$HLV_BIN" "$HLV_OTHER"
    cat > "$HLV_BINARY" <<'EOF'
#!/bin/sh
printf 'argument: %s\n' "$@"
cat
exit 7
EOF
    chmod +x "$HLV_BINARY"

    run_installer() {
        run_test_shell -fc "${1:-} . \"\$HLV_INSTALLER\" \"\$HLV_BINARY\" \"\$HLV_BIN\"" > "$hlv_test_dir/output" 2>&1
    }

    # Free name, paths containing spaces, argument/stdin forwarding, exit status.
    run_installer </dev/null
    [[ "$HLV_BIN/hlv" -ef "$HLV_BINARY" ]]
    hlv_status=0
    printf 'stdin payload\n' | "$HLV_BIN/hlv" 'two words' '--json' > "$hlv_test_dir/forwarded" || hlv_status=$?
    [[ $hlv_status == 7 ]]
    [[ $(cat "$hlv_test_dir/forwarded") == $'argument: two words\nargument: --json\nstdin payload' ]]
    run_installer </dev/null
    [[ $(cat "$hlv_test_dir/output") == *'already installed'* ]]
    rm "$HLV_BIN/hlv"

    # Session aliases/functions are visible when sourced; EOF and Enter skip.
    run_installer 'alias hlv="echo original";' </dev/null
    [[ ! -e "$HLV_BIN/hlv" ]]
    [[ $(cat "$hlv_test_dir/output") == *'Conflict:'*'Skipped'* ]]
    run_installer 'hlv() { echo original; };' <<< ''
    [[ ! -e "$HLV_BIN/hlv" ]]

    # Choose another name, retry conflicts and reject path traversal.
    run_installer 'alias hlv="echo original"; alias viewer="echo other";' <<< $'../escape\nviewer\nmy-hlv'
    [[ ! -e "$HLV_BIN/hlv" && ! -e "$HLV_BIN/viewer" ]]
    [[ "$HLV_BIN/my-hlv" -ef "$HLV_BINARY" ]]
    [[ ! -e "$HLV_BIN/../escape" ]]
    rm "$HLV_BIN/my-hlv"

    # Executables elsewhere on PATH, including a later shadowed command.
    cp "$HLV_BINARY" "$HLV_OTHER/hlv"
    run_installer 'PATH="$HLV_OTHER:$PATH";' </dev/null
    [[ ! -e "$HLV_BIN/hlv" ]]
    [[ $(cat "$hlv_test_dir/output") == *'existing executable'* ]]
    ln -s "$HLV_BINARY" "$HLV_BIN/hlv"
    run_installer 'PATH="$HLV_BIN:$HLV_OTHER:$PATH";' </dev/null
    [[ $(cat "$hlv_test_dir/output") == *'Conflict:'*'Skipped'* ]]
    rm "$HLV_BIN/hlv" "$HLV_OTHER/hlv"

    # Non-executable files, directories, and broken symlinks at the destination.
    printf 'keep this file\n' > "$HLV_BIN/hlv"
    run_installer </dev/null
    [[ $(cat "$HLV_BIN/hlv") == 'keep this file' ]]
    rm "$HLV_BIN/hlv"
    mkdir "$HLV_BIN/hlv"
    run_installer </dev/null
    [[ -d "$HLV_BIN/hlv" && ! -e "$HLV_BIN/hlv/$(basename "$HLV_BINARY")" ]]
    rmdir "$HLV_BIN/hlv"
    ln -s "$hlv_test_dir/missing" "$HLV_BIN/hlv"
    run_installer </dev/null
    [[ $(readlink "$HLV_BIN/hlv") == "$hlv_test_dir/missing" ]]
    rm "$HLV_BIN/hlv"

    # The source script preserves the caller's alias/function and directory.
    run_test_shell -fc 'alias hlv="echo original"; before=$PWD; . "$HLV_INSTALLER" "$HLV_BINARY" "$HLV_BIN"; test "$PWD" = "$before"; alias hlv' </dev/null > "$hlv_test_dir/output" 2>&1
    [[ $(cat "$hlv_test_dir/output") == *'hlv='*'echo original'* ]]

    # Invalid/missing targets fail before creating a shortcut.
    if run_installer 'HLV_BINARY="$HLV_OTHER/missing";' </dev/null; then
        echo 'Missing target unexpectedly succeeded' >&2
        exit 1
    fi
    [[ ! -e "$HLV_BIN/hlv" ]]
    printf 'Shortcut tests passed in %s\n' "$(basename "$hlv_shell")"
done
