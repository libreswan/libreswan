#!/bin/sh
# a config that fails during IKE_AUTH

set -e

args="--esp aes $@"
./oe.sh ${args}

RUN() {
    echo :
    echo : OE ${args}
    echo " $@"
    "$@"
}

# expect outer trap and possibly a negotation shunt
RUN ../../guestbin/ipsec-kernel-policy.sh

RUN ../../guestbin/wait-for-pluto.sh --timeout 10 --match '#1: initiator established IKE SA'
RUN ../../guestbin/wait-for-pluto.sh --timeout 10 --match '#2: IKE_AUTH response rejected Child SA'
# doesn't happen; bug
RUN echo ../../guestbin/wait-for-pluto.sh --timeout 10 --match '#1: deleting IKE SA'

# expect outer trap and possibly a failure shunt
RUN ../../guestbin/ipsec-kernel-policy.sh

# everything should be gone
RUN ipsec showstates

# leaving only the bare shunts
RUN ipsec shuntstatus
