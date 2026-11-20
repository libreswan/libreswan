#!/bin/sh

exec </dev/null
set -xe
set -o pipefail

PREFIX=@@KVM_PREFIX@@

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
# Packages used to build libreswan.
#
# These track updates.  Notably, NSS.
#

build_packages() {
    cat <<EOF | awk '{print $1}'
ElectricFence
audit-libs-devel
c++				# Building NSS
clang
gdb				# debugging the build
gyp				# Building NSS
ldns-devel
libcurl-devel
libseccomp-devel
libselinux-devel
make
ninja				# Building NSS
nss-devel
nss-tools
nss-util-devel
pam-devel
strace				# debugging the build
unbound
unbound-devel
valgrind			# debugging the build
xmlto
EOF
}

#
# Kernel packages.
#
# These do not update to avoid drift.
#

kernel_packages() {
    cat <<EOF | awk '{print $1}'
kernel
kernel-devel
EOF
}

#
# Test Packages
#
# These do not update to avoid drift.
#

test_packages() {
    cat <<EOF | awk '{print $1}'
bind-dnssec-utils
bind-utils
checksec
conntrack-tools
diffstat			# used by NSRUN
fping
gawk
git				# used by NSRUN
gnutls-utils			# used by soft tokens
iptables
jq
kl2tpd
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
rsync
selinux-policy-devel
socat
softhsm-devel			# used by soft tokens
sshpass				# used by ansible-playbook
strongswan
strongswan-sqlite
systemtap			# performance profiling
tar
tcpdump
time				# aka /bin/time
tpm2-abrmd
vim-enhanced
wireshark-cli
EOF
}


:
: Install the release version of all packages.
:

dnf install -y --disable-repo '*updates*' $(build_packages)
dnf install -y --disable-repo '*updates*' $(test_packages)
dnf install -y --disable-repo '*updates*' $(kernel_packages)


:
: Now upgrade build dependencies to mainline.
:

dnf upgrade -y $(build_packages)


:
: INSTALL and DISABLE systemd-networkd and systemd-resolved
:
: - put back /etc/resolv.conf trashed by systemd-resolved
: - systemd-networkd has not configs, hence ...
: - leave NetworkManager enabled
: - transmogrify.sh will configure systemd-networkd
:

ls -l /etc/resolv.conf # file

dnf install -y systemd-networkd systemd-resolved
dnf upgrade -y systemd-networkd systemd-resolved
systemctl disable systemd-resolved.service systemd-networkd.service
systemctl enable NetworkManager # to be sure

ls -l /etc/resolv.conf # link ARGH
rm /etc/resolv.conf
touch /etc/resolv.conf
