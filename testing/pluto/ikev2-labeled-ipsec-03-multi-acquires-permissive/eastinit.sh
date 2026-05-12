/testing/guestbin/swan-prep --hostkeys
# build install se module
../../guestbin/semodule.sh ipsecspd.te
# get pluto going
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add labeled
ipsec _getpeercon_server -d 4300
echo "initdone"
