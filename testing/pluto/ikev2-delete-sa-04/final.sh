# There should be no IKE SA and no IPsec SA
ipsec whack --trafficstatus
# east howvever, should be attempting to connect to west because it has auto=start
ipsec status |grep STATE_
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
