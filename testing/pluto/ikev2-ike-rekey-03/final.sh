ipsec whack --trafficstatus
ipsec status |grep STATE_ | sort
# there should be only one IKE_INIT exchange created on west
hostname | grep west > /dev/null && grep "STATE_PARENT_I1: sent v2I1, expected v2R1" /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
