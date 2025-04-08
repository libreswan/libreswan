/testing/guestbin/swan-prep
# install selinux; generated in OUTPUT by east
semodule -i OUTPUT/ipsecspd.pp
# start pluto
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add labeled
echo "initdone"
