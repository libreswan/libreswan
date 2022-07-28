/testing/guestbin/swan-prep --x509 --x509name key2032
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec whack --impair revival
echo "initdone"
