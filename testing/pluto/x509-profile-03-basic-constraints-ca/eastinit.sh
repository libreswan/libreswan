/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/`hostname`.p12

# Import a broken root CA (lacks BasicConstraint ca=y)
/testing/x509/import.sh bc-n-ca/root.p12
ipsec certutil -L -n bc-n-ca

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add east
echo "initdone"
