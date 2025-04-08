/testing/guestbin/swan-prep --x509
ipsec certutil -D -n road
ipsec certutil -D -n north
ipsec certutil -D -n east
cp road-ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24"  >> /etc/ipsec.d/policies/private-or-clear
restorecon -R /etc/ipsec.d
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
# ensure for tests acquires expire before our failureshunt=2m
echo 30 > /proc/sys/net/core/xfrm_acq_expires

# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 9,' -- ipsec auto --status

# one packet, which gets eaten by XFRM, so east does not initiate
../../guestbin/ping-once.sh --forget -I 192.1.3.33 192.1.2.23

# wait on OE IKE negotiation
../../guestbin/wait-for.sh --match private-or-clear -- ipsec whack --trafficstatus

# ping should succeed through tunnel (road pings once, north twice)
# should show established tunnel and no bare shunts
../../guestbin/ping-once.sh --up -I 192.1.3.33 192.1.2.23
../../guestbin/ping-once.sh --up -I 192.1.3.33 192.1.2.23
ipsec whack --trafficstatus
ipsec whack --shuntstatus
ipsec _kernel state
ipsec _kernel policy
iptables -t nat -L -n
