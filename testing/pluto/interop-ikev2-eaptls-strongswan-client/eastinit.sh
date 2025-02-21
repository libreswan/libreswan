/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/`hostname`.all.p12
/testing/x509/import.sh real/mainca/nic.end.cert

ipsec start
ipsec auto --add rw-eap
echo "initdone"
