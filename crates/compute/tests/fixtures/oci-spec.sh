#!/bin/sh
[ "$1" = spec ] || exit 99
printf '%s' '{"process":{},"root":{},"linux":{"namespaces":[]},"mounts":[]}' > config.json
