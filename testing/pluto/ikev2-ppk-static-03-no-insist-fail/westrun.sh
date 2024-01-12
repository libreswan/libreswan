ipsec whack --impair suppress_retransmits
# this should fail
ipsec auto --up westnet-eastnet-ipv4-psk-ppk
echo done
