/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/revoked.all.p12
/testing/x509/import.sh real/mainca/nic.end.cert

# In strict mode, without up-to-date CRL, EAST unconditionally rejects
# all CERTS.
/testing/x509/import.sh real/mainca/crl-is-up-to-date.crl

ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add east

echo "initdone"
