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
bison
build-essential
flex
gawk
libcap-ng-dev
libcurl4-nss-dev
libevent-dev
libldns-dev
libnss3
libnss3-dev
libnss3-tools
libpam0g-dev
libunbound-dev
make
net-tools
python3-pexpect
pkg-config
xmlto
iptables
nftables
EOF
