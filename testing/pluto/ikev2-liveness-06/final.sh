# should show there are no tunnels up
ipsec whack --trafficstatus
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
