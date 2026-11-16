#!/bin/sh
mode=$(cat "$0.mode") || exit 99
case "$1" in
state)
    case "$mode" in
    churn) echo "container $2 does not exist" >&2; exit 1 ;;
    absent) ;;
    delete)
        if [ ! -f "$0.deleted" ]; then cat "$0.state"; exit 0; fi ;;
    *) exit 99 ;;
    esac
    printf "error opening file \`/run/user/1000/crun/$2/status': No such file or directory\n" >&2
    exit 1 ;;
delete)
    [ "$mode" = delete ] || exit 99
    : > "$0.deleted"
    echo 'state disappeared during delete' >&2
    exit 1 ;;
list)
    if [ -f "$0.inventory" ]; then cat "$0.inventory"; fi
    code=$(cat "$0.list-exit") || exit 99
    case "$code" in 0|1) exit "$code" ;; *) exit 99 ;; esac ;;
*) exit 1 ;;
esac
