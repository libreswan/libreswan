#!/bin/sh

set ipsec certutil -L -n $1
echo + "$@"
"$@" | sed -e '1,/Exponent/ d' -e '/Signature Algorithm/,$ d'
