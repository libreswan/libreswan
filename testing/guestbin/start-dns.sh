#!/bin/sh

# not -e; systemctl has strange exit codes
set -u

# default to hidden output
echo ==== cut ====

LC_CTYPE=C
export LC_CTYPE

# install NSD config files into tmpfs mounted directory.  This way a
# reboot clears everything out.

for d in etc/nsd/conf.d etc/nsd/server.d ; do
    echo mounting $d:
    umount /$d || true
    mount -t tmpfs tmpfs /$d
    cp -av /testing/baseconfigs/all/$d/* /$d
    restorecon -R /$d
done

# Fix NSD's port.
#
# Once unbound work properly replace the next lines.
#
# XXX: huh?
#
# The idea is to point NSD on port 53 at UNBOUND, or is that UNBOUND
# on port 53 at NSD?

sed -i -e 's/5353/53/' /etc/nsd/server.d/nsd-server-libreswan.conf
for f in /etc/nsd/server.d/nsd-server-libreswan.conf /etc/nsd/nsd.conf ; do
    echo checking $f:
    grep port: $f
    grep 53 $f
done

# cp -av /testing/baseconfigs/all/etc/unbound /etc/
# cp -av /testing/baseconfigs/all/etc/systemd/system/unbound.service /etc/systemd/system/
# restorecon -R /etc/unbound

echo ==== tuc ====
echo starting dns
echo ==== cut ====

# next lines are combination nsd-keygen.service and nsd.service
/usr/sbin/nsd-control-setup -d /etc/nsd/
# fork and run in the background
/usr/sbin/nsd -c /etc/nsd/nsd.conf

# only interested in errors
$(dirname $0)/wait-for.sh --match 'notice: nsd started' -- systemctl status nsd > /dev/null

# grr, dig writes dns lookup failures to stdout.  Need to save stdout
# and then, depending on the exit code, display it.

domain=road.testing.libreswan.org

echo ==== tuc ====
echo digging for ${domain} IPSECKEY
echo ==== cut ====

dig @127.0.0.1 ${domain} IPSECKEY > /tmp/dns.log
status=$?
cat /tmp/dns.log

# These dig return code descriptions are lifted directly from the
# manual page.

echo ==== tuc ====
case ${status} in
    0) echo Everything went well, including things like NXDOMAIN.
       echo Found $(grep "^${domain}" /tmp/dns.log | wc -l) records
       ;;
    1) echo Usage error. ;;
    8) echo Could not open batch file. ;;
    9) echo No reply from server. ;;
    10) echo Internal error. ;;
    *) echo Unknown return code: $? ;;
esac
exit ${status}
