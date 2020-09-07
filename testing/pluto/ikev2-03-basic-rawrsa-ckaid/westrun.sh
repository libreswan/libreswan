# see description.txt
# should find east's pubkey using ckaid and leftrsasigkey
ipsec auto --add east-ckaid-rsasigkey
# force east/west rsasigkey load using @east/@west
ipsec auto --add east-rsasigkey
# now east's pubkey using ckaid is found
ipsec auto --add east-ckaid
echo done
