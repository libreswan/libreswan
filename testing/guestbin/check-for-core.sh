#!/bin/sh

DIR=${1:-/tmp}

BT()
{
    gdb <<EOF -quiet -nx "$@" 2>&1 | tr -cd '\12\15\40-\176' | sed -e 's/^\((gdb) \)*//'
set width 0
set height 0
set pagination no
set charset ASCII
echo \nCRASHING THREAD:\n\n
bt
echo \nINSTRUCTION:\n\n
x/i \$pc
echo \nSOURCE CODE:\n\n
list
echo \nLOCAL VARIABLES:\n\n
info locals
echo \nFUNCTION ARGUMENTS:\n\n
info args
echo \nLOCAL SCOPE:\n\n
info scope $pc
echo \nFRAME:\n\n
info frame
echo \nREGISTERS:\n\n
info registers
echo \nALL THREADS:\n\n
thread apply all bt
EOF
}

ok=true

for core in ${DIR}/core* ${DIR}/*.core ; do
    test -r "${core}" || continue

    ok=false

    echo

    # Note:
    #
    # Post-mortem scripts use the presence of the text "CORE FOUND" in
    # the console output as a marker indicating a test failing with a
    # core dump.
    echo CORE FOUND: ${core}

    case $(basename ${core}) in
	*.core ) exe=$(basename ${core} .core) ;;
	core* ) exe=$(echo $core | cut -d. -f3) ;;
	* ) exe=
    esac

    if test -z "${exe}" ; then
	echo unknown core ${core}
	continue
    elif test -r /usr/local/libexec/ipsec/${exe} ; then  # Upstream default
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
	BT ${prog} ${core}
	echo
    fi

    # send to pluto's log file
    if test "${exe}" = "pluto" -a -n "${prog}"; then
	(
	    echo
	    BT ${prog} ${core}
	    echo
	) >> /tmp/pluto.log
    fi

    cp -f $core OUTPUT/
done

${ok}
