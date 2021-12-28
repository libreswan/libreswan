#!/bin/sh

# Teardown the host, or more pointedly, shutdown any running daemons
# (pluto, strongswan, iked, ...) and then check for core dumps or
# other problems.

# Normally this script's output is sanitized away.  However when this
# script detects a failure and exits with a non-zero status then all
# the output is exposed.

set -e
ok=true

#
# A feeble attempt at making the messages consistent (and, hence,
# easier to grep).
#

CHECK() {
    test="$@"
    echo :
    echo : checking "${test}"
    echo :
}

PASS() {
    echo PASS: "${test}"
}

FAIL() {
    echo FAIL: "${test}"
    ok=false
}

IGNORE() {
    echo IGNORE: "${test}"
}

SKIP() {
    echo SKIP: "${test}" "$@"
}

RUN() {
    # a selective set +x?
    echo "$@" 1>&2
    "$@"
}

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

if test -r /run/pluto/pluto.ctl ; then
    CHECK shutting down pluto
    if ! RUN ipsec whack --shutdown ; then
	FAIL
	pluto=false
    elif RUN pidof pluto ; then
	FAIL
	pluto=false
    else
	PASS
	pluto=true
    fi
else
    echo :
    echo : pluto is not running, probably strongswan, but possibly iked
    echo :
    pluto=false
fi


CHECK core files

# If any are found, copy them to the output directory.

if $(dirname $0)/check-for-core.sh ; then
    PASS
    core=false
else
    FAIL
    core=true
fi


CHECK memory leaks

# The absence of 'leak detective found no leaks' in the log file isn't
# sufficient.  For instance a pluto self-test (in check-01) doesn't
# leave any log line.  Hence check for 'NNN leaks'

if ! ${pluto} ; then
    SKIP as pluto was not running
elif ${core} ; then
    SKIP as pluto core dumped
elif grep 'leak detective found [0-9]* leaks' /tmp/pluto.log ; then
    FAIL
    grep -e leak /tmp/pluto.log | grep -v -e '|'
else
    PASS
fi


CHECK reference leaks

# For moment don't fail when this fails.  The check is still
# experimental.  OTOH, when leaks, above, fails, this might prove
# useful.
#
# Skip this when there's a core dump (little point as refcnt failure
# is guaranteed).

if ! ${pluto} ; then
    SKIP as pluto was not running
elif ${core} ; then
    SKIP as pluto core dumped
elif awk -f /testing/utils/refcnt.awk /tmp/pluto.log ; then
    PASS
else
    FAIL
fi


CHECK xfrm errors

# Complications: linux only; some tests expect a bad value; with name
# spaces the values can't be trusted.
#
# For now just dump the non-zero values to see what gives.  Next step
# would be to snapshot the expected non-zero values so they can be
# verified?


if ! ${pluto} ; then
    SKIP as pluto was not running
elif test ! -r /proc/net/xfrm_stat ; then
    SKIP as no xfrm
elif $(dirname $0)/xfrmcheck.sh ; then
    PASS
else
    IGNORE # FAIL - ongoing research
fi


CHECK state/policy entries

# For the moment dump the tables so it is possible to access the
# damage.  Can't use ipsec-look.sh as that screws around with
# cut/paste?

if ! ${pluto} ; then
    SKIP as pluto was not running
elif test ! -r /proc/net/xfrm_stat ; then
    SKIP as no xfrm
else
    log=OUTPUT/post-mortem.$(hostname).ip-xfrm.log
    ip xfrm stat | tee -a ${log}
    ip xfrm policy | tee -a ${log}
    if test -s ${log} ; then
	IGNORE # FAIL - ongoing research
    else
	PASS
    fi
fi


CHECK selinux audit records

# Should the setup code snapshot austatus before the test is run?

if test -f /sbin/ausearch ; then
    log=OUTPUT/post-mortem.$(hostname).ausearch.log
    # ignore status, save to file as might contain key=(null), ulgh!
    ausearch -r -m avc -ts boot > ${log} 2>&1 || true
    # some warnings are OK, some are not :-(
    if test -s ${log} && \
	    grep -v \
		 -e '^type=AVC .* avc:  denied  { remount } ' \
		 -e '^type=AVC .*systemd-network' \
		 -e '^type=SYSCALL .*systemd-network' \
		 -e '^type=CWD ' \
		 -e '^type=PATH .*dbus' \
		 -e '^type=PROCTITLE.*systemd-networkd' \
		 -e '^type=PATH .* name="/run"' \
	    ${log} ; then
	FAIL

	# Output SELinux reference policy for missing rules.
	rules=OUTPUT/post-mortem.$(hostname).audit2allow.rules
	echo saving rules in ${rules}
	ausearch -r -m avc -ts boot 2>&1 | audit2allow -R | tee ${rules}
    else
	PASS
    fi
fi


echo :
echo : unload any selinux modules
echo :

# it's assumed that the name starts with ipsecspd

semodule -l | grep ^ipsecspd | while read module ; do
    echo Unloading ${module}
    RUN semodule -r ${module}
done


# tell kvmrunner

${ok}
