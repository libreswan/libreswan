ipsec _kernel state
ipsec _kernel policy
# Should be XX hits for both west (sending) and east (receiving)
grep "flags: RESERVED" /tmp/pluto.log >/dev/null && echo payload found
