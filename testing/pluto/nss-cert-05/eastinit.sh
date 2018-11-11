/testing/guestbin/swan-prep --x509
certutil -A -d sql:/etc/ipsec.d/ -n 'otherca' -t 'CT,,' -i /testing/x509/cacerts/otherca.crt
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add nss-cert
ipsec auto --status |grep nss-cert
ipsec whack --impair suppress-retransmits
echo "initdone"
