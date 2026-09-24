/testing/guestbin/swan-prep --nokeys

RUN() { echo " $@" 1>&2 ; "$@" ; }
START() { RUN ipsec pluto --config $1 ; ../../guestbin/wait-until-pluto-started; }
STATUS() { ipsec status | sed -n -e 's/.*\(ike-sa-init-full-transcript-auth=[^;]*\)[,;]/\1/p' ; }
STOP() { RUN ipsec whack --shutdown ; }

CHECK() { START $1 ; STATUS ; STOP ; }

CHECK $PWD/west.conf
CHECK $PWD/ike-sa-init-full-transcript-auth-yes.conf
CHECK $PWD/ike-sa-init-full-transcript-auth-no.conf
CHECK $PWD/ike-sa-init-full-transcript-auth-auto.conf
