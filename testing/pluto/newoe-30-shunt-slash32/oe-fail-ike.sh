# a config that fails during IKE_SA_INIT
./oe.sh --ike aes "$@"

RUN() {
    echo :
    echo " $@"
    "$@"
    echo :
}

# expect outer trap and possibly a negotation shunt
RUN ../../guestbin/ipsec-kernel-policy.sh

# ike= rejected
RUN ../../guestbin/wait-for-pluto.sh --match '#1: ignoring IKE_SA_INIT response'
RUN ../../guestbin/wait-for-pluto.sh --match '#1: deleting IKE SA'

# expect outer trap and possibly a failure shunt
RUN ../../guestbin/ipsec-kernel-policy.sh

# everything should be gone
RUN ipsec showstates

# leaving only the bare shunts
RUN ipsec shuntstatus
