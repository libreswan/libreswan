/testing/guestbin/swan-prep --x509
certutil -d sql:/etc/ipsec.d -D -n west
certutil -K -d sql:/etc/ipsec.d
ipsec showhostkey --list
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add nss-cert
ipsec auto --status |grep nss-cert
echo "initdone"
