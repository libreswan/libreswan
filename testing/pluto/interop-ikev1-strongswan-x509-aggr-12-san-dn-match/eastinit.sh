/testing/guestbin/swan-prep --x509
certutil -D -n west -d sql:/etc/ipsec.d
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add san
echo "initdone"
