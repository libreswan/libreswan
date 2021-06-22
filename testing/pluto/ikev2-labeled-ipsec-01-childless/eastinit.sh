/testing/guestbin/swan-prep
# build install se module
../../guestbin/semodule.sh ipsecspd.te
# get pluto going
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add labeled
# start the server
ipsec getpeercon_server 4300 &
echo "initdone"
