../../guestbin/ipsec-look.sh
hostname | grep nic > /dev/null || ipsec whack --trafficstatus
# A tunnel should have established
grep "negotiated connection" /tmp/pluto.log
# you should see both RSA and NULL
grep -e 'auth method: ' -e 'hash algorithm identifier' -e ': authenticated using ' /tmp/pluto.log
