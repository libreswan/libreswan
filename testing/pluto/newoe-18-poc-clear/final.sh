../../guestbin/ipsec-kernel-state.sh\n../../guestbin/ipsec-kernel-policy.sh
# should not show any hits
grep -v '^|' /tmp/pluto.log | grep "^[^|].* established Child SA"
