# should fail to establish
ipsec whack --impair suppress-retransmits
ipsec auto --up replay
echo done
