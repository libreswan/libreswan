#!/bin/sh

set -xe ; exec < /dev/null

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

# first time install; after that upgrade
upgrade="
systemd-networkd
unbound
unbound-devel
nss-devel
nss-tools
nss-util-devel
audit-libs-devel
libcurl-devel
pam-devel
libseccomp-devel
ldns-devel
libselinux-devel
xmlto
"

# only install
install="
kernel
kernel-devel
"

dnf install -y ${upgrade} ${install}
dnf upgrade -y ${upgrade}


:
: save the latest kernels
:

kernel=$(ls /boot/vmlinuz-* | sort -V | tail -1)
cp -v ${kernel} /pool/${PREFIX}fedora-upgrade.vmlinuz
ramfs=$(ls /boot/initramfs-*.img | sort -V | tail -1)
cp -v ${ramfs} /pool/${PREFIX}fedora-upgrade.initramfs
