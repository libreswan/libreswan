/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/east.all.cert
/testing/x509/import.sh real/otherca/otherwest.all.p12
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair timeout_on_retransmit
ipsec auto --add westnet-eastnet-x509-cr
echo "initdone"
