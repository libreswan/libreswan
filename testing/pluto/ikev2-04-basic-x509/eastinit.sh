/testing/guestbin/swan-prep --x509
certutil -d sql:/etc/ipsec.d -D -n west
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --add distraction
ipsec auto --status | grep westnet-eastnet-ikev2
echo "initdone"
