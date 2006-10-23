ipsec auto --up  westnet-eastnet-esp-sha1-pfs
ipsec look
ipsec auto --delete  westnet-eastnet-esp-sha1-pfs
ipsec auto --up  westnet-eastnet-esp-md5-pfs
ipsec look
echo done
