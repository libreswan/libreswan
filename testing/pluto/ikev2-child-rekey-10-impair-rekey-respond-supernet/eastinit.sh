/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add east
ipsec whack --impair revival
ipsec whack --impair rekey_respond_supernet
echo "initdone"
