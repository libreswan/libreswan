../../guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west-east
ipsec whack --impair suppress-retransmits --impair send-no-delete --impair revival
ipsec connectionstatus | grep -i -e resume -e ticket
echo "initdone"
