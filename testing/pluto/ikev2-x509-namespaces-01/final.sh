hostname | grep east > /dev/null && ipsec whack --trafficstatus
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
