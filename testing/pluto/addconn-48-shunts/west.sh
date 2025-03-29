/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec add negotiationshunt=
ipsec add negotiationshunt=passthrough
ipsec add negotiationshunt=drop
ipsec add negotiationshunt=hold

ipsec add failureshunt=
ipsec add failureshunt=none
ipsec add failureshunt=passthrough
ipsec add failureshunt=drop
ipsec add failureshunt=hold
ipsec add failureshunt=reject

ipsec add type=drop
ipsec add type=reject
ipsec add type=passthrough

ipsec connectionstatus | sed -n -e 's/\(.* policy:\) .*\(DROP\).*/\1 \2/p' | sort -u
ipsec connectionstatus | sed -n -e 's/\(.* policy:\) .*\(PASS\).*/\1 \2/p' | sort -u
ipsec connectionstatus | sed -n -e 's/\(.* policy:\) .*\(NEGO_[_A-Z]*\).*/\1 \2/p' | sort -u
ipsec connectionstatus | sed -n -e 's/\(.* policy:\) .*\(failure[_A-Z]*\).*/\1 \2/p' | sort -u
