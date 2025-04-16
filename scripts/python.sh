#!/bin/sh
dir="$(dirname "$(readlink -fm "$0")")"
FILE=$dir/.venv/bin/activate
test -f $FILE && source $FILE
exec python3 "$@"
