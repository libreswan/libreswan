/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/west.p12
/testing/x509/import.sh otherca/otherwest.p12
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --add main
ipsec auto --add other
echo "initdone"
