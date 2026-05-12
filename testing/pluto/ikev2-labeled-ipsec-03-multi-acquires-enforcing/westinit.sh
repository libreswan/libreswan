/testing/guestbin/swan-prep --hostkeys
# install selinux; generated in OUTPUT by east
semodule -i OUTPUT/ipsecspd.pp
setenforce 1
# for port re-use in tests with protoport selectors
echo 1 >/proc/sys/net/ipv4/tcp_tw_reuse
# start pluto
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add labeled
echo "initdone"
