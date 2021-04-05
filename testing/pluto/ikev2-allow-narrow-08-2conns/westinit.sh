/testing/guestbin/swan-prep

# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits

ipsec auto --add west-east-ikev2-222
ipsec auto --add west-east-ikev2-333
ipsec auto --status | grep west
