/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/east.all.p12
/testing/x509/import.sh real/mainca/crl-is-out-of-date.crl

# ipsec start
ipsec pluto --config /etc/ipsec.conf --leak-detective --impair event_check_crls
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert-crl
ipsec auto --status |grep nss-cert-crl
ipsec auto --listcrls
echo "initdone"
