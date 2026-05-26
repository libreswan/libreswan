# establish but without fragments
ipsec up westnet-eastnet-ikev2 # sanitize-retransmits
# confirm we did NOT send fragments
grep "fragment number" /tmp/pluto.log && echo "FAIL: we are not allowed to send fragments"
echo done
