#!/bin/sh

set -eu

if test $# -eq 0 ; then
    cat <<EOF 1>&2
Usage: $0 <host> [ <mount> ]
List <host>s kvm mounts.
If <mount> is specified, just print that mount's path.
EOF
    exit 1
fi

host=$1 ; shift

mount=
if test $# -gt 0; then
    mount=$1 ; shift
fi

if test $# -gt 0; then
    echo "Unexpected argument: $*" 1>&2
    exit 1
fi

sudo virsh dumpxml $host | awk '
/<filesystem type=.mount. / {
    source = ""
    target = ""
}

/<source dir=/ {
    split($2, a, /'\''/)
    source = a[2]
}

/<target dir=/ {
    split($2, a, /'\''/)
    target = a[2]
}

/<\/filesystem>/ {
    if ("'$mount'" == "") {
        print target, source
    } else if ("'$mount'" == target) {
        print source
    }
}
'
