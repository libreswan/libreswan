ipsec whack --trafficstatus
# clean up after ourselves
rm -f /etc/systemd/system/unbound.service
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
