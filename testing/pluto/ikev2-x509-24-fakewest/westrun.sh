ipsec whack --impair suppress_retransmits
ipsec whack --impair revival
# this should fail fast
ipsec auto --up westnet-eastnet-ikev2
echo done
