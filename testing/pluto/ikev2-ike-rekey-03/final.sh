ipsec whack --trafficstatus
ipsec status |grep STATE_ | sort
# there should be only one IKE_INIT exchange created
grep "STATE_UNDEFINED(ignore) => STATE_PARENT" /tmp/pluto.log  |grep parent
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
