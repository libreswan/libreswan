ipsec auto --up westnet-eastnet-esp-sha1-pfs
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
ipsec auto --delete  westnet-eastnet-esp-sha1-pfs
ipsec auto --up westnet-eastnet-esp-md5-pfs
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
echo done
