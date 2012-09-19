ipsec auto --up  westnet--eastnet-ikev2

ping -n -c 2 -I 192.1.2.45 192.1.2.23
ipsec look
echo westrundone
