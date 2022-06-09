#!/bin/sh

set -xe

echo disable useless repos

for repo in fedora-modular updates-modular fedora-cisco-openh264 ; do
    echo disabling: ${repo}
    dnf config-manager --set-disable ${repo}
done

echo enable useful repos

for repo in fedora-debuginfo updates-debuginfo ; do
    echo enabling: ${repo}
    dnf config-manager --set-enable ${repo}
done

# Point the cache at /pool
dnf config-manager --save --setopt=keepcache=True
# not /pool/fedora.pkg as that matches: rm -f /pool/fedora.*
dnf config-manager --save --setopt=cachedir=/pool/pkg.fedora
#dnf config-manager --save --setopt=makecache=0

# make it explicit
dnf makecache

# "$@" contains: install-packages -- upgrade-packates
install=$(echo "$@" | sed -e 's/--.*//')
upgrade=$(echo "$@" | sed -e 's/..--//')
dnf install -y ${install}
dnf upgrade -y ${upgrade}
