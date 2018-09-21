# should fail fast
ipsec whack --impair key-length-attribute:0
ipsec whack --impair delete-on-retransmit
ipsec auto --add ike=aes128
ipsec auto --up ike=aes128
ipsec whack --impair none

echo done
