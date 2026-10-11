#!/bin/sh
# Source in your current Bash/Zsh/POSIX shell to include its aliases/functions.
# Optional arguments: path to http_logviewer, destination directory.
# A subshell keeps variables and directory changes out of the caller's session.
(
    hlv_target=${1:-}
    hlv_bin_dir=${2:-${NIMBLE_DIR:-$HOME/.nimble}/bin}
    if [ -z "$hlv_target" ]; then
        hlv_target=$(command -v http_logviewer 2>/dev/null) || hlv_target=
        if [ ! -f "$hlv_target" ] && [ -x ./build/http_logviewer ]; then
            hlv_target=./build/http_logviewer
        fi
    fi
    if [ ! -f "$hlv_target" ] || [ ! -x "$hlv_target" ]; then
        printf '%s\n' 'Build or install http_logviewer first, or pass its executable path.' >&2
        exit 1
    fi
    hlv_target=$(cd -- "$(dirname -- "$hlv_target")" && printf '%s/%s\n' "$PWD" "$(basename -- "$hlv_target")") || exit 1
    mkdir -p -- "$hlv_bin_dir" || exit 1
    hlv_bin_dir=$(cd -- "$hlv_bin_dir" && pwd -P) || exit 1
    hlv_name=hlv

    while :; do
        case "$hlv_name" in
            ''|[!a-zA-Z0-9_]*|*[!a-zA-Z0-9_-]*)
                printf '%s\n' 'Use a command name containing only letters, digits, underscores, or hyphens.' >&2
                hlv_conflict=yes ;;
            *)
                hlv_conflict=no
                hlv_destination=$hlv_bin_dir/$hlv_name
                hlv_existing=$(command -v "$hlv_name" 2>/dev/null) || hlv_existing=
                # Bash can hide aliases from command -v in non-interactive
                # sessions, so inspect the alias table explicitly as well.
                if alias "$hlv_name" >/dev/null 2>&1; then
                    printf 'Conflict: ' >&2
                    alias "$hlv_name" >&2
                    hlv_conflict=yes
                elif [ -n "$hlv_existing" ] && { [ "$hlv_existing" = "$hlv_name" ] || ! [ "$hlv_existing" -ef "$hlv_target" ]; }; then
                    printf 'Conflict: ' >&2
                    command -V "$hlv_name" >&2
                    hlv_conflict=yes
                fi
                # Inspect every PATH entry, including commands currently shadowed
                # by an alias, function, or earlier executable.
                hlv_path_rest=${PATH:-}
                while :; do
                    hlv_path_dir=${hlv_path_rest%%:*}
                    hlv_candidate=${hlv_path_dir:-.}/$hlv_name
                    if [ -f "$hlv_candidate" ] && [ -x "$hlv_candidate" ] && ! [ "$hlv_candidate" -ef "$hlv_target" ]; then
                        printf 'Conflict: existing executable %s\n' "$hlv_candidate" >&2
                        hlv_conflict=yes
                    fi
                    case "$hlv_path_rest" in
                        *:*) hlv_path_rest=${hlv_path_rest#*:} ;;
                        *) break ;;
                    esac
                done
                if { [ -e "$hlv_destination" ] || [ -L "$hlv_destination" ]; } && ! [ "$hlv_destination" -ef "$hlv_target" ]; then
                    printf 'Conflict: destination already exists: %s\n' "$hlv_destination" >&2
                    hlv_conflict=yes
                fi ;;
        esac
        if [ "$hlv_conflict" = no ]; then
            if [ "$hlv_destination" -ef "$hlv_target" ]; then
                printf 'Shortcut already installed: %s\n' "$hlv_destination"
            else
                # Never force replacement of an existing file or symlink.
                ln -s "$hlv_target" "$hlv_destination" || exit 1
                printf 'Installed %s -> %s\n' "$hlv_destination" "$hlv_target"
            fi
            case ":${PATH:-}:" in
                *":$hlv_bin_dir:"*) ;;
                *) printf 'Add %s to PATH to use %s.\n' "$hlv_bin_dir" "$hlv_name" ;;
            esac
            exit 0
        fi
        printf 'Enter a different shortcut name, or press Enter to skip: ' >&2
        IFS= read -r hlv_name || hlv_name=
        if [ -z "$hlv_name" ]; then
            printf '%s\n' 'Skipped shortcut installation; existing commands and configuration are unchanged.'
            exit 0
        fi
    done
)
