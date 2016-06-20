/testing/guestbin/swan-prep --x509
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# this should succeed
ipsec auto --add modecfg-east-21
# these should fail due to overlapping address pools
ipsec auto --add modecfg-east-20
ipsec auto --add modecfg-road-east
echo initdone
