/testing/guestbin/swan-prep --46 --x509
certutil -A -n bigkey -t P,, -d  sql:/etc/ipsec.d -i /testing/x509/certs/bigkey.crt 
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add v6-tunnel
echo "initdone"
