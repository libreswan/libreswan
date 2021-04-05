# see description.txt
ipsec auto --add west-ckaid-east-rsasigkey
ipsec auto --up west-ckaid-east-rsasigkey
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
