ipsec whack --trafficstatus
# ESP should not show TFC
grep " IPsec SA established tunnel mode" /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
