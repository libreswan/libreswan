../../guestbin/ipsec-kernel-state.sh\n../../guestbin/ipsec-kernel-policy.sh
# a tunnel should have established
grep "^[^|].* established Child SA" /tmp/pluto.log
