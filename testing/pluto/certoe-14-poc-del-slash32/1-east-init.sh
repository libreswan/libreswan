/testing/guestbin/swan-prep  --x509
../../guestbin/ip.sh route del default
ip tuntap add mode tun tun0
ifconfig tun0 10.13.13.13/24
../../guestbin/ip.sh route add default via 10.13.13.1
../../guestbin/ip.sh route add 192.1.3.0/24 via 192.1.2.254
ipsec certutil -D -n road
ipsec certutil -D -n east
cp east-ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
cp policies/* /etc/ipsec.d/policies/
echo "192.1.3.209/32"  >> /etc/ipsec.d/policies/private
restorecon -R /etc/ipsec.d
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 10,' -- ipsec auto --status
echo "initdone"
