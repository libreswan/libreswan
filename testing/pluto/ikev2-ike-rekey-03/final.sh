ipsec whack --trafficstatus
ipsec status |grep STATE_ | sort
# there should be only one IKE_INIT exchange
grep "STATE_PARENT_I1 with STF_OK" /tmp/pluto.log
grep "STATE_PARENT_R1 with STF_OK" /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
