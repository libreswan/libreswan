# On east this shows the duplicates on west there is nothing.
grep "received duplicate [^ ]* message request .* fragment" /tmp/pluto.log | sed "s/last_contact=.[^ ]* /last_contact=XXX /g"
../../guestbin/ipsec-look.sh
