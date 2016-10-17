#!/bin/sh

set -ex

prefix=krb.

# To run GSSAPI/Kerberos tests, nic needs to be configured as KDC and
# west and east need to join the kerberos domain.

# Please note that some of these commands take a very long time. Don't
# abort them when they seem slow.

# Create/update the clone and install some packages.
#
# Since this modifies the .cow2 file that the test domains depend on,
# first remove the test domains.
#
# To force a scratch build of the clone domain, run:
#
#   make uninstall-kvm-clone-domain
#
# before running this script.

make KVM_PREFIX=${prefix} \
     uninstall-kvm-test-domains

make KVM_PREFIX=${prefix} \
     install-kvm-clone-domain

./testing/utils/kvmsh.py \
    ${prefix}clone dnf install -y \
    bind \
    bind-dyndb-ldap \
    bind-utils \
    freeipa-admintools \
    freeipa-client \
    freeipa-server

./testing/utils/kvmsh.py \
    ${prefix}clone dnf debuginfo-install -y \
    bind \
    bind-dyndb-ldap \
    freeipa-admintools \
    freeipa-client \
    freeipa-server


# Pre-install/update libreswan on clone.
#
# This hack avoids having to install libreswan on the individual
# domains.

make KVM_PREFIX=${prefix} \
     KVM_BUILD_DOMAIN=${prefix}clone \
     kvm-install-${prefix}clone


# Create the test domains from the clone.

make KVM_PREFIX=${prefix} \
     install-kvm-test-domains


# Transmogrify the domains using swan-transmogrify.sh.
#
# Transmogrifying involes things like fixing up the host name, hosts
# file, and network interfaces, and adding some default configuration
# files.
#
# Unlike the python swan-transmogrify script used to transmogrify
# normal test hosts, this script:
#
#  - is run once; swan-transmogrify, which would be run from rc.local
#    on every reboot, is disabled
#
#  - deals with FQDNs (/etc/hosts, /etc/hostname) needed by kerberos

for host in nic east west ; do
    ./testing/utils/kvmsh.py \
	--shutdown --chdir . ${prefix}${host} \
	./testing/guestbin/swan-transmogrify.sh \
	${host}.testing.libreswan.org
done


# Create the KDC on nic.
#
# This leaves NIC running, should it?

./testing/utils/kvmsh.py \
    ${prefix}nic \
    ipa-server-install \
    -r TESTING.LIBRESWAN.ORG \
    -n testing.libreswan.org \
    -p swanswan -P swanswan -a swanswan \
    --no-ntp \
    --no-sshd \
    --unattended


# Add east and west to the kerberos domain:

for host in east west ; do \
    ./testing/utils/kvmsh.py \
	--shutdown ${prefix}${host} \
	ipa-client-install \
	--enable-dns-updates \
	--domain=testing.libreswan.org \
	--server=nic.testing.libreswan.org \
	--realm=TESTING.LIBRESWAN.ORG \
	-p admin \
	-w swanswan \
	--hostname=${host}.testing.libreswan.org \
	--no-ntp \
	--no-ssh \
	--no-sshd \
	--fixed-primary \
	--unattended
done


# Finally, run a test case to prove all is ok.

make KVM_PREFIX=${prefix} \
     KVM_TESTS=testing/pluto/ikev2-gssapi-01 \
     kvm-test
