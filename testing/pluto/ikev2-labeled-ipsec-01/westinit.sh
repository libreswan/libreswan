/testing/guestbin/swan-prep
echo 3 > /proc/sys/net/core/xfrm_acq_expires
# generated in OUTPUT by east
( cd OUTPUT && semodule -i ipsecspd.pp )
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add labeled
echo "initdone"
