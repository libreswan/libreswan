/testing/guestbin/swan-prep --nokeys
# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair major_version_bump
ipsec whack --impair timeout_on_retransmit
ipsec whack --impair revival
ipsec auto --add westnet-eastnet-ikev2-major
echo "initdone"
