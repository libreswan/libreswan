# should fail to establish
ipsec whack --debug-all --impair-retransmits
ipsec auto --up replay
echo done
