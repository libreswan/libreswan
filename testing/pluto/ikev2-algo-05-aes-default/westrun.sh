ipsec auto --up  westnet-eastnet-aes-128
ipsec auto --delete  westnet-eastnet-aes-128
ipsec auto --add  westnet-eastnet-aes-256
ipsec auto --up  westnet-eastnet-aes-256
ipsec auto --add  westnet-eastnet-aes-mix
ipsec auto --up  westnet-eastnet-aes-mix
echo done
