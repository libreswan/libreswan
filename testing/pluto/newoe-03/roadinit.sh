/testing/guestbin/swan-prep
named -c /etc/bind/named.conf
cp policies/* /etc/ipsec.d/policies/
# shorten acquire from 30s to 1s - prob not needed
echo 1 > /proc/sys/net/core/xfrm_acq_expires
ip addr add 192.1.3.210/24 dev eth0
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
echo "initdone"
