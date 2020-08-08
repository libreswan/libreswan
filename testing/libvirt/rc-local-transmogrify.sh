#!/bin/sh

exec > /tmp/rc.local.txt 2>&1
set -x

SELINUX=$(getenforce)
echo getenforce: ${SELINUX}
setenforce Permissive


hostname=$(hostname)
echo hostname: ${hostname}
if test -z "${hostname}"; then
    echo "ERROR: Failed to find our swan hostname based on the mac match knownlist " 1>&2
    exit 1
fi

# and resolv.conf

resolv="/testing/baseconfigs/${hostname}/etc/resolv.conf"
if test -r "${resolv}" ; then
    cp -av "${resolv}" /etc/resolv.conf
fi


# and some custom ipsec* files, but not directories

# XXX: this at least partially duplicates swan-prep?

if test -d /etc/ipsec.d -a ! -d /etc/ipsec.d.stock ; then
    mv -v /etc/ipsec.d /etc/ipsec.d.stock
else
    rm -rf /etc/ipsec.d
fi
cp -rv /testing/baseconfigs/all/etc/ipsec.d /etc/ipsec.d
find /etc/ipsec.d -name ipsec.conf.common | xargs rm -f
cp -av /testing/baseconfigs/${hostname}/etc/ipsec.* /etc/

# fixup the nss files that are root-only on a real host, but are world-read
# in our repository so the qemu user can still read it to copy it

if test -f /etc/ipsec.d/pkcs11.txt; then
    chmod 600 /etc/ipsec.d/pkcs11.txt
fi
chmod 600 /etc/ipsec.d/*.db

# SElinux fixup
restorecon -R /etc/

echo restore SELINUX to ${SELINUX}
setenforce ${SELINUX}

if test ${hostname} != swanbase; then
    rm -vf /etc/rc.d/rc.local
fi
