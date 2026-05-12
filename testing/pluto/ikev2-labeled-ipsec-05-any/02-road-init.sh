/testing/guestbin/swan-prep --hostkeys
# install selinux; generated in OUTPUT by east
semodule -i OUTPUT/ipsecspd.pp
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add labeled
echo "initdone"
