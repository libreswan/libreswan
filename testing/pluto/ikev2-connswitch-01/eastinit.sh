/testing/guestbin/swan-prep --x509
certutil -d sql:/etc/ipsec.d -D -n west
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
ipsec auto --add distraction
ipsec auto --status | grep westnet-eastnet
echo "initdone"
