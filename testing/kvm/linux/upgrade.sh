#!/bin/sh

exec </dev/null
set -xe
set -o pipefail

PREFIX=@@PREFIX@@

:
: disable useless repos
:

for repo in fedora-cisco-openh264 ; do
    echo disabling: ${repo}
    dnf config-manager --set-disable ${repo}
done


:
: enable useful repos
:

for repo in fedora-debuginfo updates-debuginfo ; do
    echo enabling: ${repo}
    dnf config-manager --set-enable ${repo}
done


:
: Point the cache at /pool/pkg.fedora.NNN
:

cachedir=$( . /etc/os-release ; echo /pool/pkg.${ID}.${VERSION_ID} )
dnf config-manager --save --setopt=keepcache=True
dnf config-manager --save --setopt=cachedir=${cachedir}

#dnf config-manager --save --setopt=makecache=0

:
: give network time to come online!
:

sleep 5


:
: explicitly build the cache
:

dnf makecache


:
: limit kernel to two installs
:

# https://ask.fedoraproject.org/t/old-kernels-removal/7026/2
sudo sed -i 's/installonly_limit=3/installonly_limit=2/' /etc/dnf/dnf.conf


:
: Install then upgrade
:

# stuff needed to build libreswan; this is first installed and then
# constantly upgraded

building() {
    cat <<EOF | awk '{print $1}'
ElectricFence
audit-libs-devel
make
ldns-devel
libcurl-devel
libseccomp-devel
libselinux-devel
nss-devel
nss-tools
nss-util-devel
pam-devel
unbound
unbound-devel
xmlto
EOF
}

# latest kernel; this is only installed (upgrading kernels is not a
# fedora thing).  XL2TPD sucks in the latest kernel so is included in
# the list.

kernel() {
    cat <<EOF | awk '{print $1}'
kernel
kernel-devel
xl2tpd
EOF
}

# utilities used to test libreswan; these are only installed for now
# (so that there isn't too much version drift).

testing() {
    cat <<EOF | awk '{print $1}'
bind-dnssec-utils
bind-utils
conntrack-tools
fping
gdb
ike-scan
iptables
libcap-ng-utils
libfaketime
linux-system-roles
nc
net-tools
nftables
nsd
ocspd
openssl
python3-netaddr
python3-pexpect
python3-pyOpenSSL
rsync
selinux-policy-devel
socat
sshpass					used by ansible-playbook
strace
strongswan
strongswan-sqlite
systemd-networkd
tar
tcpdump
vim-enhanced
wireshark-cli
EOF
}

dnf install -y `building` `testing` `kernel`
dnf upgrade -y `building` `testing`


:
: save the latest kernels
:

kernel=$(ls /boot/vmlinuz-* | sort -V | tail -1)
cp -vf ${kernel} /pool/${PREFIX}linux-upgrade.vmlinuz
ramfs=$(ls /boot/initramfs-*.img | sort -V | tail -1)
cp -vf ${ramfs} /pool/${PREFIX}linux-upgrade.initramfs
