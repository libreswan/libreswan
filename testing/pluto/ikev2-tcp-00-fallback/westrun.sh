# this will 'fail' on the first attempt. The second attempt
# happens in the background and succeeds using TCP
# see: https://github.com/libreswan/libreswan/issues/368
ipsec auto --up ikev2-westnet-eastnet
sleep 3
ping -n -q -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
# should show tcp being used
../../guestbin/ipsec-look.sh | grep encap
ipsec auto --down ikev2-westnet-eastnet
echo "done"
