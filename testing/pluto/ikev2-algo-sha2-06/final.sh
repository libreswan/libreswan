# stop on east caused crash on west at some point in the past
hostname |grep west > /dev/null || ipsec stop
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
