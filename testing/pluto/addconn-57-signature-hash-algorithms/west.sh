/testing/guestbin/swan-prep --nokeys

RUN() { echo " $@" 1>&2 ; "$@" ; }
START() { RUN ipsec pluto --config $1 ; ../../guestbin/wait-until-pluto-started; }
STATUS() { ipsec status | sed -n -e 's/.*\(signature-hash-algorithms=[^;]*\)[,;]/\1/p' ; }
STOP() { RUN ipsec whack --shutdown ; }

CHECK() { START $1 ; STATUS ; STOP ; }

CHECK $PWD/west.conf
CHECK $PWD/signature-hash-algorithms-yes.conf
CHECK $PWD/signature-hash-algorithms-no.conf
CHECK $PWD/signature-hash-algorithms-auto.conf
