/testing/guestbin/swan-prep --x509
certutil -d sql:/etc/ipsec.d -D -n west
certutil -A -i /testing/x509/cacerts/otherca.crt -d sql:/etc/ipsec.d -n "otherca" -t 'CT,,'
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add nss-cert-correct
ipsec auto --add nss-cert-wrong
ipsec auto --status |grep nss-cert
echo "initdone"
