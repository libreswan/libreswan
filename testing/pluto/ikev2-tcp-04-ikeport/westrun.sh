# unfortunately does not yet indicate it is using TCP
ipsec auto --up ikev2-westnet-eastnet
ping -n -q -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
# should show tcp being used
../../guestbin/ipsec-look.sh | grep encap
ipsec auto --down ikev2-westnet-eastnet
echo "done"
