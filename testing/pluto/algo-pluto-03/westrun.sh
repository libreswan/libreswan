ipsec auto --up  westnet-eastnet-ah-sha1-pfs
ipsec look
ipsec auto --delete  westnet-eastnet-ah-sha1-pfs
ipsec auto --up  westnet-eastnet-ah-md5-pfs
ipsec look
echo done
