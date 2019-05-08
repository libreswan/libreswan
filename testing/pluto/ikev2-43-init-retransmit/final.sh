../../pluto/bin/ipsec-look.sh
hostname | grep east > /dev/null && grep ikev2-responder-retransmit /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
