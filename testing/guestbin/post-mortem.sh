#!/bin/sh

# Teardown the host, or more pointedly, shutdown any running daemons
# (pluto, strongswan, iked, ...) and then check for core dumps or
# other problems.

# Normally this script's output is sanitized away.  However should
# this script exit with a non-zero status then all the output is
# exposed.

set -ex
ok=true

# Shutdown pluto
#
# What about strongswan / iked / ...?

echo shutting down

ps ajx | sed -n \
	     -e '1 p' \
	     -e '/sed/        {n;}' \
	     -e '/pluto/      {p;n;}' \
	     -e '/strongswan/ {p;n;}' \
	     -e '/iked/       {p;n;}'

if test -r /tmp/pluto.log ; then
    ipsec stop
fi


# Check for core files
#
# If any are found, copy them to the output directory.

echo checking for core files

if $(dirname $0)/check-for-core.sh ; then
    echo no core files found
else
    echo core file found
    ok=false
fi


# check there were no memory leaks

echo checking for leaks

if test -r /tmp/pluto.log ; then
    # check-01 selftests pluto and that doesn't run leak detective so
    # the absense of 'leak detective found no leaks' isn't sufficient.
    if grep 'leak detective found [0-9]* leaks' /tmp/pluto.log ; then
	echo memory leaks found
	ok=false
	grep -e leak /tmp/pluto.log | grep -v -e '|'
    fi
fi


# check for selinux warnings
#
# Should the setup code snapshot austatus before the test is run?

echo checking for selinux audit records

if test -f /sbin/ausearch ; then
    log=OUTPUT/$(hostname).ausearch.log
    # ignore status
    ausearch -r -m avc -ts boot 2>&1 | tee ${log}
    # some warnings are OK, some are not :-(
    if test -s ${log} && grep -v \
	    -e '^type=AVC .* avc:  denied  { remount } ' \
	    ${log} ; then
	echo selinux audit records found
	ok=false
    fi
fi


# tell kvmrunner

${ok}
