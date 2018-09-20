/testing/guestbin/swan-prep
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair major-version-bump
ipsec whack --impair delete-on-retransmit
ipsec auto --add westnet-eastnet-ikev2-major
echo "initdone"
