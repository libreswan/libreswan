#!/bin/sh

# Teardown the host, or more pointedly, shutdown any running daemons
# (pluto, strongswan, iked, ...) and then check for core dumps or
# other problems.

# Normally this script's output is sanitized away.  However should
# this script exit with a non-zero status then all the output is
# exposed.

set -e
ok=true


echo
echo shut down pluto
echo

# Sometimes pluto gets turned into a zombie.  The PS line hopefully
# shows it.  Should this also detect and fail when that happens (ipsec
# stop will hang anyway).
#
# What about strongswan / iked / ...?

ps ajx | sed -n \
	     -e '1 p' \
	     -e '/sed/        {n;}' \
	     -e '/pluto/      {p;n;}' \
	     -e '/strongswan/ {p;n;}' \
	     -e '/iked/       {p;n;}'

if test -r /tmp/pluto.log ; then
    ipsec stop
fi

echo
echo check for core files
echo

# If any are found, copy them to the output directory.

if $(dirname $0)/check-for-core.sh ; then
    echo no core files found
else
    echo core file found
    ok=false
fi


echo
echo check for leaks
echo

# The absense of 'leak detective found no leaks' in the log file isn't
# sufficient.  For instance a pluto self-test (in check-01) doesn't
# leave any log line.  Hence check for 'NNN leaks'

if test -r /tmp/pluto.log && grep 'leak detective found [0-9]* leaks' /tmp/pluto.log ; then
    echo memory leaks found
    ok=false
    grep -e leak /tmp/pluto.log | grep -v -e '|'
fi


echo
echo check reference counts
echo

# For moment don't fail when this fails.  The check is still
# experimental.  OTOH, when leaks, above, fails, this might prove
# useful.

if test -r /tmp/pluto.log && ! awk -f /testing/utils/refcnt.awk /tmp/pluto.log ; then
    echo reference counts are off
    #ok=false -- see above, not yet
fi


echo
echo checking for selinux audit records
echo

# Should the setup code snapshot austatus before the test is run?

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

	# Output SELinux reference policy for missing rules.
	rules=OUTPUT/$(hostname).audit2allow.rules
	ausearch -r -m avc -ts boot 2>&1 | audit2allow -R | tee ${rules}
    fi
fi



echo
echo unload any selinux modules
echo

# it's assumed that the name starts with ipsecspd

semodule -l | grep ^ipsecspd | while read module ; do
    echo Unloading ${module}
    semodule -r ${module}
done



# tell kvmrunner

${ok}
