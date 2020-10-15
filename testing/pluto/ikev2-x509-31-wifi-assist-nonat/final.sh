# should show two full sets of policies on both road and east
ip xfrm policy
: ==== cut ====
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
