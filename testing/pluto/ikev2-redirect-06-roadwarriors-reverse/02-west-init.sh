/testing/guestbin/swan-prep --nokeys
# pretend to be east
/testing/x509/import.sh real/mainca/east.all.p12

../../guestbin/ip.sh route del 192.0.2.0/24
ifconfig eth0:1 192.0.2.254/24
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add east-any
echo initdone
