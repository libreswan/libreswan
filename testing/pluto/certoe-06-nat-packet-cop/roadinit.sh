/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/road.p12
ipsec certutil -D -n road
cp road-ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
cp policies/* /etc/ipsec.d/policies/
echo "192.1.2.0/24"  >> /etc/ipsec.d/policies/private-or-clear
restorecon -R /etc/ipsec.d
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 9,' -- ipsec auto --status
ip -s xfrm monitor > /tmp/xfrm-monitor.out & sleep 1
echo "initdone"
