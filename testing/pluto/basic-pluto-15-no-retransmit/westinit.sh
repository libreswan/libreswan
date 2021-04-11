/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
# suffer a quick death
ipsec whack --impair delete-on-retransmit
ipsec auto --add westnet-eastnet
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"
