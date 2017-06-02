ipsec whack --trafficstatus
# this should show IKE and IPsec state for "road-east-ikev2" and not an OE group
ipsec status | grep road-east | sed 's/"road-east-ikev2".*/"road-east-ikev2" --- cut ---/' | grep "#"
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
