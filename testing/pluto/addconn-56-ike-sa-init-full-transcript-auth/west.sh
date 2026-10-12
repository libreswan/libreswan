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

ipsec stop

RUN() { echo " $@" 1>&2 ; "$@" ; }
START() { RUN ipsec pluto --config $1 ; ../../guestbin/wait-until-pluto-started; }
STATUS() { ipsec status | sed -n -e 's/.*\(ike-sa-init-full-transcript-auth=[^;]*\)[,;]/\1/p' ; }
STOP() { RUN ipsec whack --shutdown ; }

CHECK() { START $1 ; STATUS ; STOP ; }

CHECK $PWD/ike-sa-init-full-transcript-auth-default.conf
CHECK $PWD/ike-sa-init-full-transcript-auth-yes.conf
CHECK $PWD/ike-sa-init-full-transcript-auth-no.conf
CHECK $PWD/ike-sa-init-full-transcript-auth-auto.conf
