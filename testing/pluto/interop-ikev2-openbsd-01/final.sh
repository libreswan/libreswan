if [ -f /tmp/iked.log ]; then cp /tmp/iked.log OUTPUT/openbsde.iked.log ; fi
test -f /sbin/ipsecctl && ipsecctl -s all | sort
