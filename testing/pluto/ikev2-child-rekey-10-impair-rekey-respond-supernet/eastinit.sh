/testing/guestbin/swan-prep --x509
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add east
ipsec whack --impair revival
ipsec whack --impair rekey-respond-supernet
echo "initdone"
