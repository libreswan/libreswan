: ==== start ====
TESTNAME=ikev2-allow-narrow-07
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec whack --whackrecord /var/tmp/ikev2.record
ipsec auto --add  westnet--eastnet-ikev2
ipsec auto --add  westnet--eastnet-ikev2-bait1
ipsec auto --add  westnet--eastnet-ikev2-bait2
ipsec auto --add  westnet--eastnet-ikev2-bait3
ipsec auto --add  westnet--eastnet-ikev2-bait4
ipsec auto --add  westnet--eastnet-ikev2-bait5
ipsec whack --debug-control --debug-controlmore --debug-crypt
