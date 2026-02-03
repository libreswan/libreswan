/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west-east
ipsec whack --impair send_no_delete
echo "initdone"
