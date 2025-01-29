#!/bin/sh

set -xe ; exec < /dev/null

PREFIX=@@PREFIX@@

# create a package cache directory

export PKG_CACHE=/pool/pkg.openbsd.$(uname -r)
echo PKG_CACHE=${PKG_CACHE}
mkdir -p ${PKG_CACHE}

export PKG_PATH=${PKG_CACHE}:installpath

# download the packages

add() {
    pkg_add -V -v "$@"
}

add fping
add gawk
add gmake
add nss
add libevent
add libunbound
add bison
add libldns
add xmlto
add curl
add git
add bash
# stem with branch, see pkg_add
add gcc%11
add llvm%17

sync ; sync ; sync

