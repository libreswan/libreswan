/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/`hostname`.p12
/testing/x509/import.sh real/mainca/nic.end.cert

ipsec certutil -L

#normal test things:
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add nss-cert-ocsp
ipsec connectionstatus nss-cert-ocsp
echo "initdone"
