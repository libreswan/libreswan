/testing/guestbin/swan-prep --nokeys
../../guestbin/wait-until-alive 192.0.2.254
iptables -A INPUT -i eth0 -s 192.0.2.254 -p icmp -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
../../guestbin/ping-once.sh --down 192.0.2.254
ipsec start
../../guestbin/wait-until-pluto-started
../../guestbin/ip.sh route get to 192.1.2.23
# this test need --verbose to see source address selection
ipsec auto --add --verbose road
echo "initdone"
