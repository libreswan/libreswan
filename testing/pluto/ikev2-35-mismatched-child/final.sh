# this should not match anything
grep v2N_INVALID_MESSAGE_ID /tmp/pluto.log
# this shows we returned the error in IKE_AUTH
grep "exchange type:" /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
