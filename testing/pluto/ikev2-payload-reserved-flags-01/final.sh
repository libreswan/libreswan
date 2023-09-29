../../guestbin/ipsec-kernel-state.sh\n../../guestbin/ipsec-kernel-policy.sh
# Should be XX hits for both west (sending) and east (receiving)
grep "flags: RESERVED" /tmp/pluto.log >/dev/null && echo payload found
