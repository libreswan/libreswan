: ==== cut ====
ipsec look
ipsec auto --status
: ==== tuc ====
ipsec whack --shutdown
: ==== cut ====
ipsec look
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
