ipsec auto --up  westnet-eastnet-esp-sha1-pfs
../../pluto/bin/ipsec-look.sh
ipsec auto --delete  westnet-eastnet-esp-sha1-pfs
ipsec auto --up  westnet-eastnet-esp-md5-pfs
../../pluto/bin/ipsec-look.sh
echo done
