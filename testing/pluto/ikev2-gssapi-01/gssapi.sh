#!/bin/sh

set -ex

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

make kvm-purge

make kvmsh-clone \
     KVMSH_COMMAND="dnf install -y \
     bind \
     bind-dyndb-ldap \
     bind-utils \
     freeipa-admintools \
     freeipa-client \
     freeipa-server"

make kvmsh-clone \
     KVMSH_COMMAND="dnf debuginfo-install -y \
     bind \
     bind-dyndb-ldap \
     freeipa-admintools \
     freeipa-client \
     freeipa-server"


# Pre-build/install/update libreswan on clone.
#
# This hack avoids having to install libreswan on the individual
# domains.
#
# Need to set KVM_BUILD_DOMAIN to the clone domain as otherwise it
# will build/install using the default build domain (which is 'east').
# XXX: should KVM_BUILD_DOMAIN be set to 'clone'?

make kvm-clone-install \
     KVM_BUILD_DOMAIN='$(KVM_CLONE_DOMAIN)'

# Create the test domains from the clone.

make kvm-install-test-domains


# Transmogrify the domains using swan-transmogrify.sh.
#
# Transmogrifying involves things like fixing up the host name, hosts
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
    make kvmsh-${host} \
	 KVMSH_FLAGS="--chdir . --shutdown" \
	 KVMSH_COMMAND="./testing/guestbin/swan-transmogrify.sh \
	 ${host}.testing.libreswan.org"
done


# Create the KDC on nic.
#
# This leaves NIC running, should it?

make kvmsh-nic \
     KVMSH_COMMAND="ipa-server-install \
     -r TESTING.LIBRESWAN.ORG \
     -n testing.libreswan.org \
     -p swanswan -P swanswan -a swanswan \
     --no-ntp \
     --no-sshd \
     --unattended"


# Add east and west to the kerberos domain:

for host in east west ; do \
    make kvmsh-${host} \
	 KVMSH_FLAGS="--shutdown" \
	 KVMSH_COMMAND="ipa-client-install \
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
	 --unattended"
done


# Finally, run a test case to prove all is ok.

make kvm-test \
     KVM_TESTS=testing/pluto/ikev2-gssapi-01
