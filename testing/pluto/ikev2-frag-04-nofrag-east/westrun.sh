# expected to fail as east does not "support" fragmentation.
ipsec auto --up westnet-eastnet-ikev2
# confirm we did NOT send fragments
grep "fragment number" /tmp/pluto.log && echo "FAIL: we are not allowed to send fragments"
echo done
