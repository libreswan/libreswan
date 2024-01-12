/testing/guestbin/swan-prep --x509
ipsec crlutil -I -i /testing/x509/crls/needupdate.crl
ipsec certutil -D -n west
# ipsec start
ipsec pluto --config /etc/ipsec.conf --leak-detective --impair event_check_crls
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert-crl
ipsec auto --status |grep nss-cert-crl
ipsec auto --listcrls
echo "initdone"
