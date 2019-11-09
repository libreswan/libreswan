ipsec whack --impair suppress-retransmits --impair revival
ipsec auto --add road-east-2
ipsec auto --up road-east-2
ping -n -c 4 -I 192.1.3.209 192.1.2.23
: ==== end ====
