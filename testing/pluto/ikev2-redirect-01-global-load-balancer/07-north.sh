ipsec auto --add north-east
ipsec auto --up north-east
echo "3. north connection add+up done"
sleep 1
# should be connected to west!
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec whack --trafficstatus
ipsec auto --delete north-east
echo "3. north connection delete done"
