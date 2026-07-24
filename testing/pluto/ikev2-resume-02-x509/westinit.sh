../../guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/west.p12
/testing/x509/import.sh real/mainca/east.end.cert
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west-east
ipsec whack --impair suppress-retransmits --impair send-no-delete --impair revival
ipsec connectionstatus | grep -i -e resume -e ticket
echo "initdone"
