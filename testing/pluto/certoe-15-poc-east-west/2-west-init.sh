/testing/guestbin/swan-prep --x509
ip route del default
ip route add default via 192.9.4.1
certutil -D -n east -d sql:/etc/ipsec.d
cp west-ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
cp policies/* /etc/ipsec.d/policies/
# specific /32 to test replacement of /32 oppo-instance with oppo-group
echo "192.1.2.23/32"  >> /etc/ipsec.d/policies/private
restorecon -R /etc/ipsec.d
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
# give OE policies time to load
sleep 5
ip -s xfrm monitor > /tmp/xfrm-monitor.out &
echo "initdone"
