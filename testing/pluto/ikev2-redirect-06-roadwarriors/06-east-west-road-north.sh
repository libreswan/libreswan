ipsec whack --trafficstatus | sed -e "s/#./#X/" -e "s/\[[0-9]\]/[X]/" | sort
: ==== cut ====
ipsec auto --status
ip xfrm state
ip xfrm policy
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
