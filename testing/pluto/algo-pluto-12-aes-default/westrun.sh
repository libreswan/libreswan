ipsec auto --add westnet-eastnet-aes-default
ipsec auto --up westnet-eastnet-aes-default
ipsec auto --delete westnet-eastnet-aes-default
#
ipsec auto --add westnet-eastnet-aes-128
ipsec auto --up westnet-eastnet-aes-128
ipsec auto --delete westnet-eastnet-aes-128
#
ipsec auto --add westnet-eastnet-aes-256
ipsec auto --up westnet-eastnet-aes-256
ipsec auto --delete westnet-eastnet-aes-256
#
ipsec auto --add  westnet-eastnet-aes-mix-1
ipsec auto --up  westnet-eastnet-aes-mix-1
ipsec auto --delete  westnet-eastnet-aes-mix-1
#
ipsec auto --add  westnet-eastnet-aes-mix-2
ipsec auto --up  westnet-eastnet-aes-mix-2
ipsec auto --delete  westnet-eastnet-aes-mix-2
echo done
