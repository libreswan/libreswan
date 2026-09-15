/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec add ikev1-transcript=
ipsec add ikev1-transcript=yes
ipsec add ikev1-transcript=no
ipsec add ikev1-transcript=auto

ipsec add ikev2-transcript=
ipsec add ikev2-transcript=yes
ipsec add ikev2-transcript=no
ipsec add ikev2-transcript=auto

ipsec connectionstatus | sed -n -e 's/\(.* policy:\) .*\([A-Z_]*IKE_SA_INIT_FULL_TRANSCRIPT_AUTH[A-Z_]*\).*/\1 \2/p' | sort
