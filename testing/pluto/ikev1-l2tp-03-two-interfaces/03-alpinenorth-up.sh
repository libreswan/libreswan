ipsec up l2tp-north-to-east-on-north

# give the kernel messages time to appear
echo "c server" > /var/run/xl2tpd/l2tp-control ; sleep 5
../../guestbin/ping-once.sh --up 192.0.2.254

ipsec whack --trafficstatus | grep -v "inBytes=0" | sed "s/type=ESP.*$/[...]/"
