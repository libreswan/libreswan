ipsec auto --up ikev2-west-east
ping -n -c 4 192.1.2.23
ipsec whack --trafficstatus
# should show tcp being used
../../pluto/bin/ipsec-look.sh | grep encap
../../pluto/bin/ipsec-look.sh
ipsec auto --down ikev2-west-east
echo "done"
