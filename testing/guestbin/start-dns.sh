#!/bin/sh

# not -e; systemctl has strange exit codes
set -u

# Stop systemctl going all graphical
LC_CTYPE=C
export LC_CTYPE

# default to hidden output
echo ==== cut ====

# Install NSD and UNBOUND config files into a tmpfs mounted
# directories.  This way a reboot clears everything out.
#
# NSD only requires a few tweaks; UNBOUND replaces everything :-/

for d in etc/nsd/conf.d etc/nsd/server.d etc/unbound ; do
    echo tmpfs mounting $d:
    umount /$d || true
    mount -t tmpfs tmpfs /$d
    cp -av /testing/baseconfigs/all/$d/* /$d
    restorecon -R /$d
done

# same for /var/run
for d in /run/nsd /run/unbound ; do
    echo tmpfs mounting $d:
    umount $d || true
    mount -t tmpfs tmpfs $d
done

echo ==== tuc ====
echo starting dns
echo ==== cut ====

/testing/guestbin/nsd-start.sh start
/testing/guestbin/unbound-start.sh start

# grr, dig writes dns lookup failures to stdout.  Need to save stdout
# and then, depending on the exit code, display it.

domain=road.testing.libreswan.org

echo ==== tuc ====
echo digging for ${domain} IPSECKEY
echo ==== cut ====

# Probe NSD directly before probing it via UNBOUND.

for port in 5353 53 ; do
    log=/tmp/dns.${port}.log
    dig -p ${port} @127.0.0.1 ${domain} IPSECKEY > ${log}
    status=$?
    echo dig ${port} returned ${status}
    cat ${log}
    test ${status} -eq 0 || break
done

# These dig return code descriptions are lifted directly from the
# manual page.

echo ==== tuc ====
case ${status} in
    0) echo Everything went well, including things like NXDOMAIN.
       echo Found $(grep "^${domain}" ${log} | wc -l) records
       ;;
    1) echo "Usage error (port ${port})." ;;
    8) echo "Could not open batch file (port ${port})." ;;
    9) echo "No reply from server (port ${port})." ;;
    10) echo "Internal error (port ${port})." ;;
    *) echo "Unknown error: ${status} (port ${port}).";;
esac

exit ${status}
