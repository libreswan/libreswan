# north is redirected to 1 - 192.1.2.44 - which is down
ipsec whack --impair none
ipsec whack --impair revival --impair timeout_on_retransmit
ipsec auto --add north-east
ipsec auto --up north-east
ipsec whack --impair trigger_revival:1
ipsec auto --delete north-east
