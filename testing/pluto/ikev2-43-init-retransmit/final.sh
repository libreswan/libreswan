../../pluto/bin/ipsec-look.sh
grep retransmits: /tmp/pluto.log | sed -e 's/current time is [.0-9]*/current time is .../'
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
