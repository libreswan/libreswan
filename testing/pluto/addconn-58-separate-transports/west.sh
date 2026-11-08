/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec add ikev1-separate=
ipsec add ikev1-separate=yes
ipsec add ikev1-separate=no
ipsec add ikev1-separate=auto

ipsec add ikev2-separate=
ipsec add ikev2-separate=yes
ipsec add ikev2-separate=no
ipsec add ikev2-separate=auto

ipsec connectionstatus | sed -n -e 's/\(.* policy:\) .*\([A-Z_]*SEPARATE_TRANSPORTS[A-Z_]*\).*/\1 \2/p' | sort
