/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/east.all.p12
/testing/x509/import.sh otherca/root.cert
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert
ipsec auto --status |grep nss-cert
ipsec whack --impair suppress_retransmits
echo "initdone"
