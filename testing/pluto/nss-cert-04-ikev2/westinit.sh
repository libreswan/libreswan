/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/west.all.p12
/testing/x509/import.sh real/otherca/otherwest.all.p12
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair timeout_on_retransmit
ipsec auto --add nss-cert
ipsec auto --status |grep nss-cert
ipsec whack --impair suppress_retransmits
echo "initdone"
