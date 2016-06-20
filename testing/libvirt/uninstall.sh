#!/bin/sh

TESTING=$(dirname $(readlink -f $0))
TESTDIR=$(dirname $TESTING)
LIBRESWANSRCDIR=$(dirname $TESTDIR)

source ${LIBRESWANSRCDIR}/kvmsetup.sh

cd $LIBRESWANSRCDIR

make uninstall-kvm-networks uninstall-kvm-domains KVM_POOLDIR=$POOLSPACE KVM_OS=$OSTYPE
