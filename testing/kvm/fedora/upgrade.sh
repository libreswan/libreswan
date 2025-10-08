#!/bin/sh

exec </dev/null
set -xe
set -o pipefail

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
mkdir -p ${cachedir}
dnf config-manager setopt keepcache=1
dnf config-manager setopt cachedir=${cachedir}
dnf config-manager setopt system_cachedir=${cachedir}

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

#
# Build packages are installed then upgraded
#

packages_for_build() {
    cat <<EOF | awk '{print $1}'
ElectricFence
audit-libs-devel
ldns-devel
libcurl-devel
libseccomp-devel
libselinux-devel
make
nss-devel
nss-tools
nss-util-devel
pam-devel
unbound
unbound-devel
xmlto
EOF
}

#
# Kernel packages are only installed to avoid drift.
#

kernel_packages() {
    cat <<EOF | awk '{print $1}'
kernel
kernel-devel
xl2tpd
EOF
}

#
# Packages needed for testing are only installed to avoid drift.
#

packages_for_testing() {
    cat <<EOF | awk '{print $1}'
bind-dnssec-utils
bind-utils
conntrack-tools
fping
gawk
gdb
gnutls-utils				used by soft tokens
ike-scan
iptables
libcap-ng-utils
linux-system-roles
nc
net-tools
nftables
nsd
ocspd
openssl
python3-netaddr
python3-pexpect
python3-pyOpenSSL
rsync
selinux-policy-devel
socat
softhsm-devel				used by soft tokens
sshpass					used by ansible-playbook
strace
strongswan
strongswan-sqlite
systemd-networkd
tar
tcpdump
tpm2-abrmd
valgrind
vim-enhanced
wireshark-cli
EOF
}

:
: Install build dependencies, testing, and kernel packages
:

dnf install -y $(packages_for_build) $(packages_for_testing) $(kernel_packages)

:
: Upgrade build dependencies
:

dnf upgrade -y $(packages_for_build)

:
: Pre-release packages pulled from updates testing
:

# dnf upgrade -y --enable-repo=updates-testing strongswan

packages="
https://kojipkgs.fedoraproject.org//packages/strongswan/6.0.2/4.fc42/x86_64/strongswan-6.0.2-4.fc42.x86_64.rpm
https://kojipkgs.fedoraproject.org//packages/strongswan/6.0.2/4.fc42/x86_64/strongswan-sqlite-6.0.2-4.fc42.x86_64.rpm
"

rpms=
for package in ${packages} ; do
    rpm=${cachedir}/$(basename ${package})
    curl --location --continue-at - --output ${rpm} "${package}"
    rpms="${rpms} ${rpm}"
done

dnf upgrade -y ${rpms}
