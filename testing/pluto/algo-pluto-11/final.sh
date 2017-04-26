ipsec look
grep calc_dh_shared /tmp/pluto.log | sed "s/@0x.*, size/@0xXXXX, size/g"
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
