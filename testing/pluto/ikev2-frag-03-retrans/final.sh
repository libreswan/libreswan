grep "retransmits:" /tmp/pluto.log | sed -e 's/current time .*/current time .../'
ipsec look
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
