#!/bin/sh
# Nimble pre-install check. Source in an interactive shell to see its aliases.
(
    hlv_nimble_dir=${NIMBLE_DIR:-$HOME/.nimble}
    hlv_conflict=no

    hlv_owned_by_viewer() {
        # A shortcut from an older release pointing to the main command is safe
        # to replace. Native Nimble executables are identified by their package.
        [ "$1" -ef "$hlv_nimble_dir/bin/http_logviewer" ] && return 0
        [ -L "$1" ] || return 1
        hlv_link=$(readlink "$1") || return 1
        case "$hlv_link" in
            /*) ;;
            *) hlv_link=$(dirname "$1")/$hlv_link ;;
        esac
        hlv_package_dir=$(cd -- "$(dirname "$hlv_link")" 2>/dev/null && pwd -P) || return 1
        case "$hlv_package_dir" in
            "$hlv_nimble_dir"/pkgs/http_logviewer-*|"$hlv_nimble_dir"/pkgs2/http_logviewer-*)
                [ "$(basename "$hlv_link")" = hlv ] &&
                    [ -f "$hlv_package_dir/http_logviewer.nimble" ] ;;
            *) return 1 ;;
        esac
    }

    if alias hlv >/dev/null 2>&1; then
        printf 'Conflict: ' >&2
        alias hlv >&2
        hlv_conflict=yes
    else
        hlv_existing=$(command -v hlv 2>/dev/null) || hlv_existing=
        if [ -n "$hlv_existing" ] && { [ "$hlv_existing" = hlv ] || ! hlv_owned_by_viewer "$hlv_existing"; }; then
            printf 'Conflict: ' >&2
            command -V hlv >&2
            hlv_conflict=yes
        fi
    fi

    hlv_path_rest=${PATH:-}
    while :; do
        hlv_path_dir=${hlv_path_rest%%:*}
        hlv_candidate=${hlv_path_dir:-.}/hlv
        if [ -f "$hlv_candidate" ] && [ -x "$hlv_candidate" ] && ! hlv_owned_by_viewer "$hlv_candidate"; then
            printf 'Conflict: existing executable %s\n' "$hlv_candidate" >&2
            hlv_conflict=yes
        fi
        case "$hlv_path_rest" in
            *:*) hlv_path_rest=${hlv_path_rest#*:} ;;
            *) break ;;
        esac
    done
    hlv_destination=$hlv_nimble_dir/bin/hlv
    if { [ -e "$hlv_destination" ] || [ -L "$hlv_destination" ]; } && ! hlv_owned_by_viewer "$hlv_destination"; then
        printf 'Conflict: destination already exists: %s\n' "$hlv_destination" >&2
        hlv_conflict=yes
    fi
    if [ "$hlv_conflict" = yes ]; then
        printf '%s\n' "Nimble will install hlv in $hlv_destination, replacing that file if present." >&2
        printf '%s\n' 'Other PATH commands may be shadowed; aliases and functions remain unchanged.' >&2
        printf 'Continue installing both commands? [y/N] ' >&2
        IFS= read -r hlv_answer || hlv_answer=
        case "$hlv_answer" in
            y|Y|yes|YES) ;;
            *) printf '%s\n' 'Installation cancelled; resolve the hlv conflict and retry.' >&2; exit 1 ;;
        esac
    fi
)
