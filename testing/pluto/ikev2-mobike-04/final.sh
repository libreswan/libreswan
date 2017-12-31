ip xfrm state
ip xfrm pol
ipsec whack --trafficstatus
sleep 7
: ==== cut ====
then ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
