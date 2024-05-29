ipsec auto --up road
../../guestbin/ping-once.sh --up -I 2001:db8:0:3:1::0 2001:db8:0:2::254
ipsec trafficstatus
../../guestbin/ip-addr-show.sh
../../guestbin/route.sh -6
../../guestbin/route.sh get to 2001:db8:1:2::23
#
# addconn need a non existing --ctlsocket
# otherwise this add bring the connection down.
#
# see the source address selection when the tunnel is established
ipsec auto --add --verbose --ctlsocket /run/pluto/foo road
echo done
