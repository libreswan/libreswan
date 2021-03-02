/testing/guestbin/swan-prep
checkmodule -M -m -o ipsec-test-module.mod ipsec-test-module.te
semodule_package -o ipsec-test-module.pp -m ipsec-test-module.mod
semodule -i ipsec-test-module.pp > /dev/null 2>/dev/null
rm -f ipsec-test-module.mod ipsec-test-module.pp
setenforce 1
ipsec start
/testing/pluto/bin/wait-until-pluto-started
echo 1 > /proc/sys/net/core/xfrm_acq_expires
ipsec auto --add labeled
echo "initdone"
