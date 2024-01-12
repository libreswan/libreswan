# should fail to establish
ipsec whack --impair suppress_retransmits
ipsec auto --up replay
echo done
