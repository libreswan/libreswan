ipsec whack --trafficstatus
# clean up after ourselves
rm -f /etc/systemd/system/unbound.service
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
