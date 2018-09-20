/testing/guestbin/swan-prep --x509
certutil -D -n road -d sql:/etc/ipsec.d
certutil -D -n north -d sql:/etc/ipsec.d
certutil -D -n east -d sql:/etc/ipsec.d
cp road-ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24"  >> /etc/ipsec.d/policies/private-or-clear
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
# ensure for tests acquires expire before our failureshunt=2m
echo 30 > /proc/sys/net/core/xfrm_acq_expires
# give OE policies time to load
sleep 5
# one packet, which gets eaten by XFRM, so east does not initiate
ping -n -c 1 -I 192.1.3.33 192.1.2.23
# wait on OE IKE negotiation
sleep 1
ping -n -c 2 -I 192.1.3.33 192.1.2.23
# ping should succeed through tunnel
# should show established tunnel and no bare shunts
ipsec whack --trafficstatus
ipsec whack --shuntstatus
../../pluto/bin/ipsec-look.sh
iptables -t nat -L -n
echo done
echo "initdone"
