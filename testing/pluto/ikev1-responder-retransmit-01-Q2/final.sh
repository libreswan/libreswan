../../guestbin/ipsec-kernel-state.sh\n../../guestbin/ipsec-kernel-policy.sh
ipsec stop
grep -e '; already' -e 'discarding packet' /tmp/pluto.log
