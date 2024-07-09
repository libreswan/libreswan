# confirm PPK was used
grep "PPK used in IKE_INTERMEDIATE" /tmp/pluto.log
# confirm west sent 2 different PPK_IDENTITY_KEY notifies
hostname | grep west > /dev/null && grep "PPK_ID: 50 50 4b 49  44 41" /tmp/pluto.log
hostname | grep west > /dev/null && grep "PPK_ID: 50 50 4b 49  44 42" /tmp/pluto.log

ipsec whack --shutdown
