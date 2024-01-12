# we are expecting to fail
ipsec whack --impair suppress_retransmits
ipsec whack --impair revival
ipsec auto --up westnet-eastnet-ikev2
echo done
