/testing/guestbin/swan-prep --x509
certutil  -d sql:/etc/ipsec.d -D -n east
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert-ocsp
ipsec auto --status |grep nss-cert-ocsp
echo "initdone"
# hang-around
ipsec whack --impair suppress-retransmits
ipsec auto --up nss-cert-ocsp
echo done
