/testing/guestbin/swan-prep --x509
certutil -D -n west -d /etc/ipsec.d
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add ikev2-westnet-eastnet-x509-cr
echo "initdone"
