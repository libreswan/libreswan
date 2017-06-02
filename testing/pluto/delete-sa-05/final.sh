# one IPsec SA should be up and one ISAKMP SA should be there
ipsec whack --trafficstatus
ipsec status |grep west-east
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
