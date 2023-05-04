# north is redirected to 1 - 192.1.2.44 - which is down
ipsec whack --impair none
ipsec whack --impair revival --impair timeout-on-retransmit
ipsec auto --add north-east
ipsec auto --up north-east
ipsec auto --delete north-east
