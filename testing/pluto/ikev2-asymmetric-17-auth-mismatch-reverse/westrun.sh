ipsec whack --impair suppress_retransmits # expect failure response
ipsec whack --impair revival
ipsec up westnet-eastnet-ikev2
echo done
