ipsec whack --impair suppress-retransmits # expect failure response
ipsec whack --impair revival
ipsec auto --up westnet-eastnet-ikev2
echo done
