
# down before unroute; everything but trap cleared
ipsec auto --down initiator
../../guestbin/ipsec-kernel-policy.sh
../../guestbin/ipsec-kernel-state.sh

# now clear everything
ipsec unroute initiator
../../guestbin/ipsec-kernel-policy.sh
