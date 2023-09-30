../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
# A tunnel should have established
grep "^[^|].* established Child SA" /tmp/pluto.log
