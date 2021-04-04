ipsec whack --trafficstatus
# policies and state should be multiple
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
