/testing/guestbin/swan-prep --fips
/usr/bin/modutil -dbdir /etc/ipsec.d -fips true -force
/usr/bin/modutil -dbdir /etc/ipsec.d -chkfips true
fipscheck
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm with a ping
ping -n -c 4 -I 192.0.1.254 192.0.2.254
# not sure why FIPS and SElinux fails on pluto including from /testing/ in permissive mode
#setenforce 0
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
echo "initdone"
