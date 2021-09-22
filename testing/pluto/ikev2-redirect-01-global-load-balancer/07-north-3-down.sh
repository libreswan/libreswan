# north is redirected to 3 - 192.1.2.46 - which is down
ipsec whack --impair none
ipsec whack --impair revival --impair delete-on-retransmit
ipsec auto --add north-east
ipsec auto --up north-east
ipsec auto --delete north-east
