# east crashed; wait for DPD on road to trigger down
../../guestbin/wait-for.sh --no-match private-or-clear -- ipsec trafficstatus

# Since the connection failed and it is OE all the CAT policies should
# be gone leaving only the template policy.  Ditto for state.
ipsec _kernel policy
ipsec _kernel state
ipsec trafficstatus
ipsec shuntstatus

# ping again to trigger OE. packet is lost
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for-pluto.sh --match '#1: sent IKE_SA_INIT request'
../../guestbin/wait-for-pluto.sh --match '#1: sent IKE_AUTH request'
../../guestbin/wait-for-pluto.sh --match '#1: initiator established IKE SA'
../../guestbin/wait-for-pluto.sh --match '#2: initiator established Child SA using #1'

# negotiation is expected to fail at which point a failure=%pass shunt
# is installed.  Wait for that.
../../guestbin/wait-for.sh --match %pass -- ipsec shuntstatus

# With %pass installed, there's no tunnel yet pings work
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec trafficstatus
ipsec _kernel policy
