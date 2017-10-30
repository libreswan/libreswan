egrep '(inserting|handling) event (EVENT_v1_SEND_XAUTH|EVENT_v1_RETRANSMIT)' /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
