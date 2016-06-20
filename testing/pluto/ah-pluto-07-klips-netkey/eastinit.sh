/testing/guestbin/swan-prep
ip addr add 192.0.2.111/24 dev eth0
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ah-md5
ipsec auto --add westnet-eastnet-ah-sha1
echo "initdone"
