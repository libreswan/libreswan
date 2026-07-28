#!/bin/sh

entity()
{
    echo "<!ENTITY ${1} '<link linkend=\"${2}\"><option>${3}</option></link>'>"
}

for x in "$@" ; do
    d=$(basename $(dirname $x))
    s=$(basename $x .xml)

    # entity to include the relevant conn parameter description
    echo "<!ENTITY ${d}.${s} SYSTEM '$PWD/d.ipsec.conf/$d/$s.xml'>"

    # hack for left= and right=
    if test "${s}" == host ; then
	entity left ${d}.${s} left
	entity right ${d}.${s} right
	continue
    fi

    # entity to refer to the conn parameter definition
    if grep -e "<option>left${s}=" "${x}" > /dev/null ; then
	entity left${s} ${d}.${s} left${s}
    fi
    if grep -e "<option>right${s}=" "${x}" > /dev/null ; then
	entity right${s} ${d}.${s} right${s}
    fi
    if grep -e "<option>${s}=" "${x}" > /dev/null ; then
	entity ${s} ${d}.${s} ${s}
    fi
done
