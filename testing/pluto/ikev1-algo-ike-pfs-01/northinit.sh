/testing/guestbin/swan-prep
../../guestbin/wait-until-alive -I 192.0.3.254 192.0.2.254

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add northnet-eastnet-nonat
ipsec whack --impair suppress-retransmits
echo "initdone"
