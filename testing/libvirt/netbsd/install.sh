#!/bin/sh

set -xe

# packages

cat <<EOF | tee /etc/pkg_install.conf
PKG_PATH=https://cdn.NetBSD.org/pub/pkgsrc/packages/NetBSD/i386/9.2/All
EOF

: git crashes, do not know why
pkg_add git || true
pkg_add gmake
pkg_add nss
pkg_add unbound
pkg_add bison
pkg_add flex
pkg_add ldns
pkg_add xmlto
pkg_add pkg-config
pkg_add fping
pkg_add racoon2
pkg_add mozilla-rootcerts
mozilla-rootcerts install
