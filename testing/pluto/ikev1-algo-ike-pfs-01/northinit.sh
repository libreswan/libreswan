/testing/guestbin/swan-prep
../../pluto/bin/wait-until-alive -I 192.0.3.254 192.0.2.254

ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add northnet-eastnet-nonat
ipsec whack --impair suppress-retransmits
echo "initdone"
