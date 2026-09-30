ipsec whack --impair suppress_retransmits
# should fail - NSS rejects the 2032-bit key (under the FIPS 2048 minimum)
ipsec auto --up westnet-eastnet-ikev2
echo done
