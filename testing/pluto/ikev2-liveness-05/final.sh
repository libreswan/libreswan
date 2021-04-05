ipsec whack --trafficstatus
ipsec whack --shuntstatus
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
