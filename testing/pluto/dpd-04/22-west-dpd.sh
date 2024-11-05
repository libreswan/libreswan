../../guestbin/wait-for-pluto.sh --match '#1: DPD action'
../../guestbin/wait-for.sh --no-match ':' -- ipsec whack --trafficstatus
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
