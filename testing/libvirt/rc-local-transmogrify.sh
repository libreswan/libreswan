#!/bin/sh

hostname=$(hostname)
echo hostname: ${hostname}
if test -z "${hostname}"; then
    echo "ERROR: Failed to find our swan hostname based on the mac match knownlist " 1>&2
    exit 1
fi

# fixup /etc/sysctl.conf
for sysctl in "/testing/baseconfigs/${hostname}/etc/sysctl.conf" "/testing/baseconfigs/all/etc/sysctl.conf" ; do
    if test -r ${sysctl} ; then break ; fi
done
cp -v ${sysctl} /etc/sysctl.conf
sysctl -q -p

# and resolv.conf
resolv="/testing/baseconfigs/${hostname}/etc/resolv.conf"
if test -r "${resolv}" ; then
    cp -v "${resolv}" /etc/resolv.conf
fi

# and bind config - can be run on all hosts (to prevent network DNS
# packets) as well as on nic

mkdir -p /etc/bind
cp -av /testing/baseconfigs/all/etc/bind/* /etc/bind/

if test "${hostname}" = "nic" ; then
    cp -av /testing/baseconfigs/nic/etc/unbound /etc/
    cp -av /testing/baseconfigs/nic/etc/nsd /etc/
    cp -av /testing/baseconfigs/nic/etc/systemd/system/unbound.service /etc/systemd/system/
fi

# ssh

mkdir -p /etc/ssh
chown 755 /etc/ssh
mkdir -p /root/.ssh
chown 700 /root/.ssh
cp -v /testing/baseconfigs/all/etc/ssh/*key* /etc/ssh/
cp -v /testing/baseconfigs/all/root/.ssh/* /root/.ssh/
chmod 600 /etc/ssh/*key* /root/.ssh/*
restorecon -R /root/.ssh

# these files are needed for systemd-networkd too
for fname in /testing/baseconfigs/all/etc/sysconfig/* ; do
    if test -f "${fname}"; then
	cp -v "${fname}" /etc/sysconfig/
    fi
done

# SElinux fixup
chcon -R --reference /var/log /testing/pluto
restorecon -R /etc

# get rid of damn cp/mv/rm aliases for root

sed -i 's/^alias rm/# alias rm/g' /root/.bashrc
sed -i 's/^alias cp/# alias cp/g' /root/.bashrc
sed -i 's/^alias mv/# alias mv/g' /root/.bashrc

# and some custom ipsec* files, but not directories

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

# selinux does not like our /testing include files
if test hostname = "nic"; then
    setenforce 0
fi

sys.exit()
