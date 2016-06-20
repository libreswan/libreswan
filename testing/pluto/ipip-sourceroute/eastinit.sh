/sbin/ip tunnel add ip.tun mode ipip remote 192.1.2.45 local 192.1.2.23
/sbin/ifconfig ip.tun 1.1.1.3 pointopoint 2.2.2.3 netmask 0xffffffff
/sbin/ip link set ip.tun up

/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add ipip-sourceroute
ipsec auto --status
echo "initdone"
