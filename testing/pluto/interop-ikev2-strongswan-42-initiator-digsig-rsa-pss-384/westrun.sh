strongswan up westnet-eastnet-ikev2 | grep -v libcurl
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
# hash algorithm notification should be received
grep SIGNATURE_HASH_ALGO /tmp/charon.log | cut -f 2 -d "]" 
echo done
