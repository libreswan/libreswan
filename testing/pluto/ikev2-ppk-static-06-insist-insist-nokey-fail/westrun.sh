ipsec whack --impair revival
ipsec whack --impair timeout_on_retransmit
# expected to fail
ipsec auto --up westnet-eastnet-ipv4-psk-ppk
echo done
