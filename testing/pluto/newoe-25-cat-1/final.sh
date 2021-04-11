hostname | grep nic > /dev/null || ipsec whack --trafficstatus
iptables -t nat -L -n
../../guestbin/ipsec-look.sh
