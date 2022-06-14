#!/bin/sh

set -xe

# create a package cache directory

export PKG_CACHE=/pool/pkg.openbsd
mkdir -p ${PKG_CACHE}

export PKG_PATH=${PKG_CACHE}:installpath

# download the packages

add() {
    pkg_add -V -v "$@"
}

add fping
add gmake
add nss
add libevent
add libunbound
add bison
add libldns
add xmlto
add curl
add git
