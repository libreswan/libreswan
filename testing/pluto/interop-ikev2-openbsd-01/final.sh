if [ -f /tmp/iked.log ]; then cp /tmp/iked.log OUTPUT/openbsde.iked.log ; fi
test -f /sbin/ipsecctl && ipsecctl -s all | sort
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
