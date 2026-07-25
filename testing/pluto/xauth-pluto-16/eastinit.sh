/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.p12
/testing/x509/import.sh real/mainca/road.end.cert
ipsec start
../../guestbin/wait-until-pluto-started
# this should succeed
ipsec add modecfg-east-21
# these should fail due to overlapping address pools
ipsec add modecfg-east-20
ipsec add modecfg-road-east
echo initdone
