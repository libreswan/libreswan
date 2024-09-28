../../guestbin/prep.sh

# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.1.2.45 192.1.2.23

ipsec start
../../guestbin/wait-until-pluto-started

ipsec whack --impair suppress_retransmits
ipsec auto --add eastnet-westnet-ikev2

echo "initdone"
