/testing/guestbin/swan-prep --x509
certutil  -d sql:/etc/ipsec.d -D -n west
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair retransmits
ipsec auto --add nss-cert-ocsp
ipsec auto --status |grep nss-cert-ocsp
echo "initdone"
