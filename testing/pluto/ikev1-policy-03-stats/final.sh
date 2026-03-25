hostname | grep east > /dev/null && ipsec whack --globalstatus | grep -E "total.ike.ikev1.dropped|total.ike.mangled"
hostname | grep west > /dev/null && ipsec whack --globalstatus | grep -E "total.ike.ikev1.dropped|total.ike.mangled"

hostname | grep east > /dev/null && grep "sending notification INVALID_MAJOR_VERSION" /tmp/pluto.log
