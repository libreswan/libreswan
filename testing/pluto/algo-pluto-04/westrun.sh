ipsec auto --up westnet-eastnet-esp-sha1-pfs
ipsec _kernel state
ipsec _kernel policy
ipsec auto --delete  westnet-eastnet-esp-sha1-pfs
ipsec auto --up westnet-eastnet-esp-md5-pfs
ipsec _kernel state
ipsec _kernel policy
echo done
