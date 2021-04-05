/testing/guestbin/swan-prep
setenforce 1
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev1-ipsec-fail
ipsec auto --add ikev1-aggr-ipsec-fail
ipsec auto --add ikev2-ipsec-fail
#ipsec whack --impair delete-on-retransmit
echo "initdone"
