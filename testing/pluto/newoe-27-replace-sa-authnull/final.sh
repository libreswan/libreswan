# only east should show 1 tunnel, as road was restarted
ipsec whack --trafficstatus
# east shows the authnull is matched on preferred non-null connection,
# then cannot find a (non-authnull) match and rejects it. So an
# additional 'authenticated' partial state lingers
ipsec status | grep STATE_
# verify no packets were dropped due to missing SPD policies
grep -v -P "\t0$" /proc/net/xfrm_stat
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
