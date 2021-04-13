# unfortunately does not yet indicate it is using TCP
ipsec auto --up ikev2-west-east
ping -n -q -c 4 192.1.2.23
ipsec whack --trafficstatus
# should show tcp being used
../../guestbin/ipsec-look.sh | grep encap
../../guestbin/ipsec-look.sh
ipsec auto --down ikev2-west-east
echo "done"
