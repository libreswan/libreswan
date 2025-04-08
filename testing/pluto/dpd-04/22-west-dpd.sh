../../guestbin/wait-for-pluto.sh --match '#1: DPD action'
../../guestbin/wait-for.sh --no-match ':' -- ipsec whack --trafficstatus
ipsec _kernel state
ipsec _kernel policy
