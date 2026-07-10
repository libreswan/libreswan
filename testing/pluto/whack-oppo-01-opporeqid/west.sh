/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west-to-east
ipsec route west-to-east
REQID=$(ipsec status | sed -n 's/.*"west-to-east":.*reqid: \([0-9]*\);.*/\1/p')
echo "west-to-east reqid: $REQID"
ipsec whack --oppohere 192.0.1.254 --oppothere 192.0.2.254 --opporeqid $REQID > /dev/null 2>&1
grep -o "reqid lookup matched connection \"west-to-east\" (policy_id [0-9]*)" /tmp/pluto.log
