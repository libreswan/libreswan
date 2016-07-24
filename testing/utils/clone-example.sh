#!/bin/sh

set -ex

prefix=krb.

# To run GSSAPI/Kerberos tests, nic needs to be configured as KDC and
# west and east need to join the kerberos domain.

# Please note that some of these commands take a very long time. Don't
# abort them when they seem slow.

# Rebuild the clone (deletes any test domains).

make KVM_PREFIX=${prefix} \
     uninstall-kvm-clone-domain \
     install-kvm-clone-domain

# Install extra packages.

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

# Pre-build and install libreswan on clone.  More typically
# kvm-install would be used at the end.

make KVM_PREFIX=${prefix} \
     KVM_BUILD_DOMAIN=${prefix}clone \
     kvm-install-${prefix}clone

# Create the test clones

make KVM_PREFIX=${prefix} \
     install-kvm-test-domains

# Before anything else, you'll need to get nic, east, and west to have
# FQDNs (/etc/hosts and /etc/hostname).  The script
# swan-transmogrify.sh does this.  It will also disables the python
# swan-transmogrify, which is run from rc.local, as that whould undo
# all the good work we've just done.

for host in nic east west ; do
    ./testing/utils/kvmsh.py \
	--shutdown --chdir . ${prefix}${host} \
	./testing/guestbin/swan-transmogrify.sh \
	${host}.testing.libreswan.org
done

# Create the KDC on nic (should NIC be left running?):

./testing/utils/kvmsh.py \
    ${prefix}nic \
    ipa-server-install \
    -r TESTING.LIBRESWAN.ORG \
    -n testing.libreswan.org \
    -p swanswan -P swanswan -a swanswan \
    --no-ntp --no-sshd --unattended

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

# Finally, install libreswan and run a test case.

make KVM_PREFIX=${prefix} \
     KVM_TESTS=testing/pluto/ikev2-gssapi-01 \
     kvm-test
