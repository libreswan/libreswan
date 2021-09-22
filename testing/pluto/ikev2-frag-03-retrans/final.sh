# On east this shows the duplicates on west there is nothing.
grep "fragment .* duplicate Message ID" /tmp/pluto.log | sed "s/last_contact=.[^ ]* /last_contact=XXX /g"
../../guestbin/ipsec-look.sh
