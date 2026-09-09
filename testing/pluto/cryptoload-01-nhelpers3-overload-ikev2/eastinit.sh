/testing/guestbin/swan-prep --nokeys
ifconfig eth1:1 192.1.2.24 netmask 255.255.255.0
ifconfig eth1:2 192.1.2.25 netmask 255.255.255.0
ifconfig eth1:3 192.1.2.26 netmask 255.255.255.0
ifconfig eth1:4 192.1.2.27 netmask 255.255.255.0
ifconfig eth1:5 192.1.2.28 netmask 255.255.255.0
ifconfig eth1:6 192.1.2.29 netmask 255.255.255.0
#export ipsec pluto --impair helper_thread_delay:10 ...
export EF_DISABLE_BANNER=1
ipsec pluto --config /etc/ipsec.conf
../../guestbin/wait-until-pluto-started
echo "initdone"
