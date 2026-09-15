# secret sauce whack vs packet triggred.
ipsec whack --oppohere 192.1.3.209 --oppothere 192.1.2.23

../../guestbin/wait-for-pluto.sh --match '#1: sent IKE_SA_INIT request'
# expect road to send NULL auth
../../guestbin/wait-for-pluto.sh --match '#1: sent IKE_AUTH request'
# expect east to send cert
../../guestbin/wait-for-pluto.sh --match '#1: initiator established IKE SA'
../../guestbin/wait-for-pluto.sh --match '#2: initiator established Child SA'

# should show established tunnel and no bare shunts
ipsec trafficstatus
ipsec shuntstatus
ipsec _kernel state
ipsec _kernel policy
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt

# ping should succeed through tunnel
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec trafficstatus
echo done
