#!/bin/sh

set -ex

# Teardown the host, or more pointedly shutdown any running daemons
# (pluto, strongswan, iked, ...) and then check for core dumps or
# other problems.

# Normally this script's output is sanitized away.  However should
# this script exit with a non-zero status then all the output is
# exposed.

ok=true


# Shutdown pluto; what about strongswan / iked / ...

echo shutting down

if test -r /tmp/pluto.log ; then
    ipsec stop
fi


# Check for core files and if any are found, copy them to the output
# directory.

echo checking for core files

if $(dirname $0)/check-for-core.sh ; then
    echo no core files found
else
    ok=false
fi


# check there were no memory leaks

echo checking for leaks

if test -r /tmp/pluto.log ; then
    # check-01 selftests pluto and that doesn't run leak detective so
    # the absense of 'leak detective found no leaks' isn't sufficient.
    if grep 'leak detective found [0-9]* leaks' /tmp/pluto.log ; then
	ok=false
	grep -e leak /tmp/pluto.log | grep -v -e '|'
    fi
fi


# tell kvmrunner

${ok}
