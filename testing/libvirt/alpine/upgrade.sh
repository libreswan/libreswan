#!/bin/sh

set -xe ; exec < /dev/null

release=$(cat /etc/alpine-release)
cachedir=/pool/pkg.alpine.${release}
mkdir -p ${cachedir}

# enable the community repo that contains NSS

sed -i -e '/community/ s/#//' /etc/apk/repositories

apk update --cache-dir ${cachedir}

# download packages

add() {
    apk add --cache-dir ${cachedir} "$@"
}

add mandoc mandoc-doc
add apk-tools-doc

add bash bash-doc
add bison bison-doc
add bsd-compat-headers
add coreutils coreutils-doc
add curl-dev curl-doc
add flex flex-doc
add gcc gcc-doc
add git git-doc
add gmp-dev gmp-doc
add ldns-dev ldns-doc
add libcap-ng-dev libcap-ng-doc
add libevent-dev
add linux-pam-dev linux-pam-doc
add make make-doc
add musl-dev
add nspr-dev
add nss-dev
add nss-tools
add pkgconfig
add sed sed-doc
add unbound-doc unbound-dev
add xmlto xmlto-doc
