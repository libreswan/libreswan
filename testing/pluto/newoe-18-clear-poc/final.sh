ipsec whack --shuntstatus
../../guestbin/ipsec-kernel-state.sh\n../../guestbin/ipsec-kernel-policy.sh
# should not show any hits
grep "^[^|].* established Child SA" /tmp/pluto.log
