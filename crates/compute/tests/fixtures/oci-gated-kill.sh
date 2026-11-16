#!/bin/sh
[ "$1" = kill ] || exit 99
: > "$0.entered"
while [ ! -f "$0.release" ]; do sleep 0.01; done
if [ -f "$0.stderr" ]; then cat "$0.stderr" >&2; fi
code=$(cat "$0.exit") || exit 99
case "$code" in 0|1) exit "$code" ;; *) exit 99 ;; esac
