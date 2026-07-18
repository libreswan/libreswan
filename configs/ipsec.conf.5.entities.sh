#!/bin/sh

for x in "$@" ; do
    d=$(basename $(dirname $x))
    s=$(basename $x .xml)
    echo '<!ENTITY '"$d.$s"' SYSTEM "'"$PWD/d.ipsec.conf/$d/$s.xml"'">'
done
