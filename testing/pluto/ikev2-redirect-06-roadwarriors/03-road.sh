/testing/guestbin/swan-prep --x509
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-east
ipsec whack --impair revival
echo initdone
ipsec auto --up road-east
ping -n -c 4 192.0.2.254
ipsec whack --trafficstatus
echo done
