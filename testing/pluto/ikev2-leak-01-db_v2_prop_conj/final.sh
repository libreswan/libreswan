grep NO_PROPOSAL_CHOSEN /tmp/pluto.log
ipsec whack --shutdown
grep -e leak /tmp/pluto.log | grep -v -e '|'
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
