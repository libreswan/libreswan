#!/bin/sh

set -xe ; exec < /dev/null

PREFIX=@@PREFIX@@

: disable useless repos

for repo in fedora-modular updates-modular fedora-cisco-openh264 ; do
    echo disabling: ${repo}
    dnf config-manager --set-disable ${repo}
done

: enable useful repos

for repo in fedora-debuginfo updates-debuginfo ; do
    echo enabling: ${repo}
    dnf config-manager --set-enable ${repo}
done

: Point the cache at /pool, but not /pool/fedora.pkg as that matches
: /pool/fedora.*

cachedir=$( . /etc/os-release ; echo /pool/pkg.${ID}${VERSION_ID} )
dnf config-manager --save --setopt=keepcache=True
dnf config-manager --save --setopt=cachedir=${cachedir}

#dnf config-manager --save --setopt=makecache=0

: give DNS time to come online?

sleep 5

: explicitly build the cache

dnf makecache

# "$@" contains: <install-package> ... -- <upgrade-package> ...
install=$(echo "$@" | sed -e 's/--.*//')
upgrade=$(echo "$@" | sed -e 's/..--//')
dnf install -y ${install}
dnf upgrade -y ${upgrade}

# now save the latest kernels
kernel=$(ls /boot/vmlinuz-* | sort -V | tail -1)
cp -v ${kernel} /pool/${PREFIX}fedora-upgrade.vmlinuz
ramfs=$(ls /boot/initramfs-*.img | sort -V | tail -1)
cp -v ${ramfs} /pool/${PREFIX}fedora-upgrade.initramfs
