#!/usr/bin/env bash
# Real shell lookup checks, optionally followed by isolated Nimble installations.
# Child shells intentionally expand their own expressions.
# shellcheck disable=SC2016
set -euo pipefail

hlv_repo=$(cd "$(dirname "$0")/.." && pwd)
hlv_guard=$hlv_repo/src/http_logviewer/cli/check_hlv.sh
hlv_test_dir=$(mktemp -d)
trap 'rm -rf "$hlv_test_dir"' EXIT
mkdir "$hlv_test_dir/tools"
for hlv_tool in basename dirname readlink; do
    ln -s "$(command -v "$hlv_tool")" "$hlv_test_dir/tools/$hlv_tool"
done

run_guard() {
    env -i PATH="$hlv_test_dir/tools" NIMBLE_DIR="$hlv_test_dir/nimble" \
        HLV_GUARD="$hlv_guard" HLV_OTHER="$hlv_test_dir/other" \
        "$hlv_shell" -fc "${1:-} . \"\$HLV_GUARD\"" > "$hlv_test_dir/output" 2>&1
}

expect_conflict() {
    if run_guard "${1:-}" </dev/null; then
        echo 'Collision unexpectedly approved without input' >&2
        exit 1
    fi
    [[ $(cat "$hlv_test_dir/output") == *'Conflict:'*'Installation cancelled'* ]]
}

for hlv_shell in bash zsh; do
    command -v "$hlv_shell" >/dev/null || continue
    hlv_shell=$(command -v "$hlv_shell")
    mkdir -p "$hlv_test_dir/nimble/bin" "$hlv_test_dir/other"
    run_guard </dev/null
    expect_conflict 'alias hlv="echo existing";'
    expect_conflict 'hlv() { echo existing; };'
    run_guard 'alias hlv="echo existing";' <<< yes
    # Explicit rejection, and arbitrary input, cancel even with piped input.
    if run_guard 'alias hlv="echo existing";' <<< no; then exit 1; fi
    if run_guard 'alias hlv="echo existing";' <<< invalid; then exit 1; fi

    printf '#!/bin/sh\nexit 77\n' > "$hlv_test_dir/other/hlv"
    chmod +x "$hlv_test_dir/other/hlv"
    expect_conflict 'PATH="$HLV_OTHER:$PATH";'
    [[ $(cat "$hlv_test_dir/output") == *'existing executable'* ]]
    rm "$hlv_test_dir/other/hlv"

    printf 'preserve this file\n' > "$hlv_test_dir/nimble/bin/hlv"
    expect_conflict
    run_guard <<< y
    [[ $(cat "$hlv_test_dir/nimble/bin/hlv") == 'preserve this file' ]]
    rm "$hlv_test_dir/nimble/bin/hlv"
    mkdir "$hlv_test_dir/nimble/bin/hlv"
    expect_conflict
    rmdir "$hlv_test_dir/nimble/bin/hlv"
    ln -s "$hlv_test_dir/missing" "$hlv_test_dir/nimble/bin/hlv"
    expect_conflict
    [[ $(readlink "$hlv_test_dir/nimble/bin/hlv") == "$hlv_test_dir/missing" ]]
    rm "$hlv_test_dir/nimble/bin/hlv"

    # Old optional shortcuts and native Nimble launchers are safe upgrades.
    printf '#!/bin/sh\nexit 0\n' > "$hlv_test_dir/nimble/bin/http_logviewer"
    ln -s http_logviewer "$hlv_test_dir/nimble/bin/hlv"
    run_guard </dev/null
    rm "$hlv_test_dir/nimble/bin/hlv" "$hlv_test_dir/nimble/bin/http_logviewer"
    hlv_old_package=$hlv_test_dir/nimble/pkgs2/http_logviewer-0.1.0-test
    mkdir -p "$hlv_old_package"
    printf 'bin = @["http_logviewer", "hlv"]\n' > "$hlv_old_package/http_logviewer.nimble"
    printf '#!/bin/sh\nexit 0\n' > "$hlv_old_package/hlv"
    chmod +x "$hlv_old_package/hlv"
    ln -s ../pkgs2/http_logviewer-0.1.0-test/hlv "$hlv_test_dir/nimble/bin/hlv"
    run_guard 'PATH="$NIMBLE_DIR/bin:$PATH";' </dev/null
    printf '#!/bin/sh\nexit 77\n' > "$hlv_test_dir/other/hlv"
    chmod +x "$hlv_test_dir/other/hlv"
    expect_conflict 'PATH="$NIMBLE_DIR/bin:$HLV_OTHER:$PATH";'
    rm "$hlv_test_dir/nimble/bin/hlv" "$hlv_test_dir/other/hlv"
    rm -rf "$hlv_old_package"
    printf 'Installation collision checks passed in %s\n' "$(basename "$hlv_shell")"
done

if [[ ${1:-} != --nimble ]]; then exit 0; fi

# Copy the viewer's cached dependencies, keeping installation state separate
# from the user's packages and commands. Nimble ignores symlinked package dirs.
hlv_cached_dir=${HLV_TEST_NIMBLE_CACHE:-${NIMBLE_DIR:-$HOME/.nimble}}
hlv_nimble=$(command -v nimble)
hlv_nim=$(command -v nim)
hlv_install_root=$hlv_test_dir/install
mkdir -p "$hlv_install_root/pkgs2" "$hlv_test_dir/project"
for hlv_package in "$hlv_cached_dir"/pkgs2/*; do
    [[ -d "$hlv_package" ]] || continue
    case "$(basename "$hlv_package")" in
        terminal_*-*|nim_sqlite-*|sqlite3_abi-*) cp -R "$hlv_package" "$hlv_install_root/pkgs2/" ;;
    esac
done
for hlv_index in packages_official.json official-nim-releases.json nimbledata2.json; do
    if [[ -f "$hlv_cached_dir/$hlv_index" ]]; then cp "$hlv_cached_dir/$hlv_index" "$hlv_install_root/"; fi
done
cp "$hlv_repo/http_logviewer.nimble" "$hlv_repo/nim.cfg" "$hlv_test_dir/project/"
cp -R "$hlv_repo/src" "$hlv_test_dir/project/"
cd "$hlv_test_dir/project"

install_viewer() {
    # Use sh for the integration test to avoid loading the host's shell config;
    # configured/session alias checks are covered in the real-shell tests above.
    env PATH=/usr/bin:/bin SHELL=/bin/sh NIMBLE_DIR="$hlv_install_root" \
        "$hlv_nimble" --offline --useSystemNim --nim:"$hlv_nim" \
        --nimbleDir:"$hlv_install_root" install -y > "$hlv_test_dir/install.log" 2>&1
}

mkdir -p "$hlv_install_root/bin"
printf 'existing unrelated command\n' > "$hlv_install_root/bin/hlv"
if install_viewer </dev/null; then
    echo 'nimble install -y unexpectedly bypassed the collision check' >&2
    exit 1
fi
if [[ $(cat "$hlv_test_dir/install.log") != *'Installation cancelled'* ]]; then
    cat "$hlv_test_dir/install.log" >&2
    exit 1
fi
[[ $(cat "$hlv_install_root/bin/hlv") == 'existing unrelated command' ]]
[[ ! -e "$hlv_install_root/bin/http_logviewer" ]]
if ! install_viewer <<< y; then cat "$hlv_test_dir/install.log" >&2; exit 1; fi
[[ -x "$hlv_install_root/bin/http_logviewer" && -x "$hlv_install_root/bin/hlv" ]]
[[ $("$hlv_install_root/bin/hlv" --version) == $("$hlv_install_root/bin/http_logviewer" --version) ]]
cmp <("$hlv_install_root/bin/hlv" --help) <("$hlv_install_root/bin/http_logviewer" --help)
cmp <(printf '' | "$hlv_install_root/bin/hlv" --json) <(printf '' | "$hlv_install_root/bin/http_logviewer" --json)
hlv_status=0
"$hlv_install_root/bin/hlv" --invalid-option > "$hlv_test_dir/error" 2>&1 || hlv_status=$?
[[ $hlv_status != 0 ]]
hlv_installed_package=$(dirname "$(readlink -f "$hlv_install_root/bin/hlv")")
[[ -f "$hlv_installed_package/http_logviewer/cli/check_hlv.sh" ]]
[[ -f "$hlv_installed_package/http_logviewer/cli/check_hlv.ps1" ]]
# Reinstallation recognizes the package's existing hlv instead of prompting.
if ! install_viewer </dev/null; then cat "$hlv_test_dir/install.log" >&2; exit 1; fi
[[ $(cat "$hlv_test_dir/install.log") != *'Conflict:'* ]]
echo 'Nimble installed both executable names; version, help, stdin, and error handling verified.'
