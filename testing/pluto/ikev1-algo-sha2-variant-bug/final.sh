ipsec _kernel state
HEAD=$(ip xfrm state |grep "enc "|head -1)
TAIL=$(ip xfrm state |grep "enc "|tail -1)
if [ "$HEAD" = "$TAIL" ]; then echo "ERROR: inbound and outbound key are the same!"; fi
