/testing/guestbin/swan-prep --hostkeys
# install selinux; generated in OUTPUT by east
semodule -i OUTPUT/ipsecspd.pp
# start pluto
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add labeled
echo "initdone"
