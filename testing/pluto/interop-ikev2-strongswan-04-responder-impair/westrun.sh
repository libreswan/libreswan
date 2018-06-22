ipsec whack --impair omit-hash-notify
ipsec auto --up  westnet-eastnet-ikev2
ping -n -c4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
# impair should show SIGNATURE_HASH_ALGORITHMS not to be sent
grep "SIGNATURE_HASH_ALGORITHMS" /tmp/pluto.log
# Expect RSA, not DIGSIG due to the impair of sending support notify
grep "auth method" /tmp/pluto.log
echo done
