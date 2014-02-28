/testing/guestbin/swan-prep 
ipsec setup start
# openswan only - libreswan does this in _stackmanager
echo 0 >/proc/sys/net/ipv4/conf/lo/disable_xfrm
echo 0 >/proc/sys/net/ipv4/conf/lo/disable_policy
/testing/pluto/bin/wait-until-pluto-started
/usr/sbin/sshd -p 666
ipsec auto --add wide
ipsec auto --add narrow
ipsec look
echo "initdone"
