#!/bin/sh

ls /tmp/core* 2>/dev/null | while read core ; do

    echo

    # Note: Post-mortem scripts use the text "CORE FOUND" in the
    # console output as a marker for a test failing with a core dump.
    echo CORE FOUND: $core

    exe=$(echo $core | cut -d. -f3)
    if test -r /usr/local/libexec/ipsec/${exe} ; then
	prog=/usr/local/libexec/ipsec/${exe}
    else
	prog=""
    fi

    if test -n "${prog}" ; then
	echo
	gdb -q ${prog} ${core} <<EOF
bt
quit
EOF
	echo
    fi

    mv -f $core OUTPUT/
done
