/testing/guestbin/swan-prep --46 --x509
certutil -A -n key4096 -t P,, -d  sql:/etc/ipsec.d -i /testing/x509/certs/key4096.crt
ifconfig eth1 mtu 1480
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add v6-tunnel
echo "initdone"
