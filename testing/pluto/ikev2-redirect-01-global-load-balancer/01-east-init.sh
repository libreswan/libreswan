/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.p12

../../guestbin/ip.sh route del 192.0.1.0/24
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add east-any
echo initdone
