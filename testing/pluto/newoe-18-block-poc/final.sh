../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
# should not show any hits because block prevents poc from seeing traffic
grep "initiate on-demand" /tmp/pluto.log
