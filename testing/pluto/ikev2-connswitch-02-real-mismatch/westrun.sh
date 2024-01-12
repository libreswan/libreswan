ipsec auto --up westnet-eastnet-foo
# expected to fail
ipsec whack --impair timeout_on_retransmit
ipsec auto --up westnet-eastnet-bar
echo done
