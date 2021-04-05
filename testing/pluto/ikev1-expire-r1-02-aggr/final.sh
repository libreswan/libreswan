# on east, we should see no more partial state
ipsec status | grep STATE_
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
