/testing/guestbin/swan-prep
# install selinux; generated in OUTPUT by east
semodule -i OUTPUT/ipsecspd.pp
# start pluto
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair childless-v2-sec-label
echo 1 > /proc/sys/net/core/xfrm_acq_expires
ipsec auto --add labeled
echo "initdone"
