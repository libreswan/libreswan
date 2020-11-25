/testing/guestbin/swan-prep
checkmodule -M -m -o ipsec-test-module.mod ipsec-test-module.te
semodule_package -o ipsec-test-module.pp -m ipsec-test-module.mod
semodule -i ipsec-test-module.pp > /dev/null 2>/dev/null
rm -f ipsec-test-module.mod ipsec-test-module.pp
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add labeled
gcc -Wall -o OUTPUT/getpeercon_server -lselinux /source/contrib/labeled-ipsec/getpeercon_server.c
chmod 755 OUTPUT/getpeercon_server
OUTPUT/getpeercon_server 4300 &
echo "initdone"
