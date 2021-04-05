/testing/guestbin/swan-prep
# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair major-version-bump
ipsec whack --impair delete-on-retransmit
ipsec whack --impair revival
ipsec auto --add westnet-eastnet-ikev2-major
echo "initdone"
