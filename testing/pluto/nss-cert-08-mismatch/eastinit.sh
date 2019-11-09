/testing/guestbin/swan-prep --x509
certutil -D -d sql:/etc/ipsec.d -n road
certutil -D -d sql:/etc/ipsec.d -n west
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add nss-cert
ipsec auto --status |grep nss-cert
ipsec whack --impair suppress-retransmits
echo "initdone"
