../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
# should show tunnel
grep "^[^|].* established Child SA" /tmp/pluto.log
