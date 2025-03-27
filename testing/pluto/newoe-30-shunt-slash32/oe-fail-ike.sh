#!/bin/sh
# a config that fails during IKE_SA_INIT

set -e

args="--ike aes $@"
./oe.sh ${args}

RUN() {
    echo :
    echo : OE ${args}
    echo " $@"
    "$@"
}

# expect outer trap and possibly a negotation shunt
RUN ../../guestbin/ipsec-kernel-policy.sh

# ike= rejected
RUN ../../guestbin/wait-for-pluto.sh --timeout 10 --match '#1: ignoring IKE_SA_INIT response'
RUN ../../guestbin/wait-for-pluto.sh --timeout 10 --match '#1: deleting IKE SA'

# expect outer trap and possibly a failure shunt
RUN ../../guestbin/ipsec-kernel-policy.sh

# everything should be gone
RUN ipsec showstates

# leaving only the bare shunts
RUN ipsec shuntstatus
