#!/bin/sh

set -xe ; exec < /dev/null

PREFIX=@@PREFIX@@

:
: disable useless repos
:

for repo in fedora-cisco-openh264 ; do
    echo disabling: ${repo}
    dnf config-manager setopt ${repo}.enabled=0
done

:
: enable useful repos
:

for repo in fedora-debuginfo updates-debuginfo ; do
    echo enabling: ${repo}
    dnf config-manager setopt ${repo}.enabled=1
done

:
: Point the cache at /pool/pkg.fedora.NNN
:

cachedir=$( . /etc/os-release ; echo /pool/pkg.${ID}.${VERSION_ID} )
dnf config-manager setopt keepcache=1
dnf config-manager setopt cachedir=${cachedir}

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

# first time install; after that upgrade
upgrade="
audit-libs-devel
fping
ldns-devel
libcurl-devel
libseccomp-devel
libselinux-devel
nss-devel
nss-tools
nss-util-devel
pam-devel
python3-pexpect
systemd-networkd
tcpdump
unbound
unbound-devel
xmlto
"

# only install
kernel="
kernel
kernel-devel
"

dnf install -y ${upgrade} ${kernel}
dnf upgrade -y ${upgrade}


:
: save the latest kernels
:

kernel=$(ls /boot/vmlinuz-* | sort -V | tail -1)
cp -vf ${kernel} /pool/${PREFIX}fedora-upgrade.vmlinuz
ramfs=$(ls /boot/initramfs-*.img | sort -V | tail -1)
cp -vf ${ramfs} /pool/${PREFIX}fedora-upgrade.initramfs
