ipsec whack --impair suppress-retransmits
#expected to fail without a crash
ipsec auto --up  westnet-eastnet-ipv4-psk
echo done
