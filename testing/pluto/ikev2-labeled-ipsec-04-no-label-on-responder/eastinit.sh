/testing/guestbin/swan-prep
# build install se module
../../guestbin/semodule.sh ipsecspd.te
# get pluto going
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add labeled
echo "initdone"
