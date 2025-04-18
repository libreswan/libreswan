ipsec _kernel state
HEAD=$(ipsec _kernel state | grep "enc "|head -1)
TAIL=$(ipsec _kernel state | grep "enc "|tail -1)
if [ "$HEAD" = "$TAIL" ]; then echo "ERROR: inbound and outbound key are the same!"; fi
