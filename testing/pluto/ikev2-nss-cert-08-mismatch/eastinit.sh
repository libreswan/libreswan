/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.p12
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add nss-cert
ipsec status |grep nss-cert
ipsec whack --impair suppress_retransmits
echo "initdone"
