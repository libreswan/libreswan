ipsec auto --up road
ping6 -n -q -w 4 -c 2 192.0.2.254
ipsec trafficstatus 
../../guestbin/ip-addr-show.sh
ip -6 route
ip route get to 192.1.2.23
#
# addconn need a non existing --ctlsocket 
# otherwise this add bring the connection down.
#
# see the source address selection when the tunnel is established
ipsec auto --add --verbose --ctlsocket /run/pluto/foo road
echo done
