../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
# a tunnel should show up here
grep "^[^|].* established Child SA" /tmp/pluto.log
