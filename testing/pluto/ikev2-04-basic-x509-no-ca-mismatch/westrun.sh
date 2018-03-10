# we are expecting to fail
ipsec whack --impair send-no-retransmits
ipsec auto --up  westnet-eastnet-ikev2
echo done
