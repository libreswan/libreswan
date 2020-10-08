#!/bin/sh

# Teardown the host, or more pointedly shutdown any running daemons
# (pluto, strongswan, iked, ...) and then check for core dumps or
# other problems.

# Normally this script's output is sanitized away.  However should
# this script exit with a non-zero status then all the output is
# exposed.

status=0

echo in teardown

exit ${status}
