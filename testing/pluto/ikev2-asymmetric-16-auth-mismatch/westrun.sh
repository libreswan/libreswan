# expected to fail
ipsec whack --impair suppress-retransmits
ipsec whack --impair revival
ipsec auto --up westnet-eastnet-ikev2
echo done
