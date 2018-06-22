#!/bin/sh -ex

# Using a VM create the certificates in this directory.
if test $# -ne 2; then
    : Usage: $0 host dest
    exit 1
fi

libreswandir=$(cd $(dirname $(realpath -m $0)); cd ../..; pwd)

host=$1 ; shift
dest=$(realpath --relative-to=${libreswandir} -m "$1") ; shift

# go to the top directory by assuming ../testing/x509/kvm-certs.sh
cd ${libreswandir}

# Run command (a quoted parameter) on the VM
#
# XXX: Having kvmsh.py work with << and | would be nice here.
kvmsh() {
    local chdir=$1 ; shift
    ./testing/utils/kvmsh.py --chdir "${chdir}" ${host} "$@"
}

# Need to FIPS off as the script isn't allowed to use things like MD5
# when FIPS is enabled.

kvmsh . 'rm -f /etc/system-fips'
kvmsh . './testing/guestbin/fipsoff'

# Create the certificates and pack them into a tar archive.
#
# "dist_certs.py" can't create a directory called "certs/" on a 9p
# mounted file system (OSError: [Errno 13] Permission denied:
# 'certs/').  In fact, "mkdir xxx/ certs/" half fails (only xxx/ is
# created) so it might even be a problem with the mkdir call!  Get
# around this by first creating the certs in /tmp and then copying
# over a tar file.
#
# "dist_certs.py" always writes its certificates to $(dirname $0).
# Get around this by running a copy of dist_certs.py placed in /tmp.

kvmsh . 'rm -rf /tmp/x509'
kvmsh . 'mkdir /tmp/x509'
kvmsh . 'cp -f ./testing/x509/dist_certs.py /tmp/x509'
kvmsh /tmp/x509 ./dist_certs.py
kvmsh /tmp/x509 'tar cf /tmp/x509/kvm-keys.tar */ nss-pw'

# Unpack the tar archive locally.
mkdir -p ${dest}
kvmsh . "cp /tmp/x509/kvm-keys.tar ${dest}"
( cd ${dest} && tar xpf kvm-keys.tar )
rm ${dest}/kvm-keys.tar
