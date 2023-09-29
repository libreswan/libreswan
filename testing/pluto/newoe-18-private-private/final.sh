../../guestbin/ipsec-kernel-state.sh\n../../guestbin/ipsec-kernel-policy.sh
# tunnel should have been established
grep "^[^|].* established Child SA" /tmp/pluto.log
