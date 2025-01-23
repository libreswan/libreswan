/testing/guestbin/swan-prep --x509
ipsec certutil -D -n west
ipsec certutil -A -i /testing/x509/cacerts/otherca.crt -n "otherca" -t 'CT,,'
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert-correct
ipsec auto --add nss-cert-wrong
ipsec auto --status |grep nss-cert
echo "initdone"
