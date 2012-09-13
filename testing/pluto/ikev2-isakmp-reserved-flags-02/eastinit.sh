: ==== start ====
TESTNAME=ikev2-isakmp-reserved-flags-02
source /testing/pluto/bin/eastnlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec whack --whackrecord /var/tmp/ikev2.record
ipsec auto --add  westnet--eastnet-ikev2
ipsec whack --debug-all --debug-crypt --impair-send-bogus-isakmp-flag
