# On east this shows the duplicates on west there is nothing.
grep "received duplicate [^ ]* message request .* fragment" /tmp/pluto.log | sed "s/last_contact=.[^ ]* /last_contact=XXX /g"
../../pluto/bin/ipsec-look.sh
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
