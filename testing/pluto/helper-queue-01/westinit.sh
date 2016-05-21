#ipsec setup stop
#umount /var/tmp; mount /var/tmp
#umount /usr/local && mount /usr/local

# NOTE: nss threads don't use PLUTO_CRYPTO_HELPER_DEBUG!
export PLUTO_CRYPTO_HELPER_DEBUG=true

TESTNAME=helper-queue-01
source /testing/pluto/bin/westlocal.sh

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add westnet-eastnet-aggr
ipsec auto --add westnet-bogus01
ipsec auto --add westnet-bogus02
ipsec auto --add westnet-bogus03
ipsec auto --add westnet-bogus04
ipsec auto --add westnet-bogus05
ipsec auto --add westnet-bogus06
ipsec auto --add westnet-bogus07
ipsec auto --add westnet-bogus08
ipsec auto --add westnet-bogus09
ipsec auto --add westnet-bogus10

ipsec whack --name westnet-bogus01 --initiate >/dev/null &
ipsec whack --name westnet-bogus02 --initiate >/dev/null &
ipsec whack --name westnet-bogus03 --initiate >/dev/null &
ipsec whack --name westnet-bogus04 --initiate >/dev/null &
ipsec whack --name westnet-bogus05 --initiate >/dev/null &
ipsec whack --name westnet-bogus06 --initiate >/dev/null &
ipsec whack --name westnet-bogus07 --initiate >/dev/null &
ipsec whack --name westnet-bogus08 --initiate >/dev/null &
ipsec whack --name westnet-bogus09 --initiate >/dev/null &
ipsec whack --name westnet-bogus10 --initiate >/dev/null &

ipsec whack --name westnet-eastnet-aggr --initiate

echo done westinit.sh

