sleep 1
# Expecting the IKE SA of west-east and the IPsec SA of westnet-eastnet
ipsec status |grep STATE
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
