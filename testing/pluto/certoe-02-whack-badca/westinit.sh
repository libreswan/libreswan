# added different CA
/testing/guestbin/swan-prep --x509 --signedbyother
certutil -D -n east -d sql:/etc/ipsec.d
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24" >> /etc/ipsec.d/policies/private-or-clear
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# give OE policies time to load
sleep 5
echo "initdone"
