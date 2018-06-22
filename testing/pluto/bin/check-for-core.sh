#!/bin/sh

DIR=${1:-/tmp}

ls ${DIR}/core* 2>/dev/null | while read core ; do

    echo

    # Note: Post-mortem scripts use the text "CORE FOUND" in the
    # console output as a marker for a test failing with a core dump.
    echo CORE FOUND: $core

    exe=$(echo $core | cut -d. -f3)
    if test -r /usr/local/libexec/ipsec/${exe} ; then  # Upstream default
	prog=/usr/local/libexec/ipsec/${exe}
    elif test -r /usr/libexec/ipsec/${exe} ; then      # RPM
	prog=/usr/sbin/ipsec/${exe}
    elif test -r /usr/lib/ipsec/${exe} ; then	       # Debian
	prog=/usr/lib/ipsec/${exe}
    else
	prog=""
    fi

    # send to stdout
    if test -n "${prog}" ; then
	echo
	gdb -ex bt  -q -batch  ${prog} ${core}
	echo
    fi

    # send to pluto's log file
    if test "${exe}" = "pluto" -a -n "${prog}"; then
	(
	    echo
	    gdb -ex bt  -q -batch  ${prog} ${core}
	    echo
	) >> /tmp/pluto.log
    fi

    mv -f $core OUTPUT/
done
