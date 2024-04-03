#!/bin/sh

set -xe

PREFIX=@@PREFIX@@

cachedir=$( . /etc/os-release ; echo /pool/pkg.${ID}.${VERSION_ID} )

mkdir -p ${cachedir}

cat <<EOF > /etc/apt/apt.conf
Dir::Cache ${cachedir};
EOF

apt-config dump | grep Dir::Cache
apt-get update

while read p eol ; do
    apt-get install -y $p
done <<EOF
net-tools
make
build-essential
libnss3-dev
pkg-config
libevent-dev
libunbound-dev
bison
flex
libcurl4-nss-dev
libpam0g-dev
libcap-ng-dev
libldns-dev
xmlto
EOF
