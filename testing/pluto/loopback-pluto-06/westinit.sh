/testing/guestbin/swan-prep
ipsec setup start
# openswan only - libreswan does this in _stackmanager
 echo 0 >/proc/sys/net/ipv4/conf/lo/disable_xfrm
 echo 0 >/proc/sys/net/ipv4/conf/lo/disable_policy
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add loopback-west
ipsec look
echo "initdone"
