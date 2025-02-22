/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec add ikev1-ikepad=
ipsec add ikev1-ikepad=yes
ipsec add ikev1-ikepad=no
ipsec add ikev1-ikepad=auto

ipsec add ikev2-ikepad=
ipsec add ikev2-ikepad=yes
ipsec add ikev2-ikepad=no
ipsec add ikev2-ikepad=auto

ipsec connectionstatus | sed -n -e 's/\(.* policy:\) .*\([A-Z_]*IKEPAD[A-Z_]*\).*/\1 \2/p' | sort
