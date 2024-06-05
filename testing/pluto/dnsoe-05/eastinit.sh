/testing/guestbin/swan-prep
cp east-ikev2-oe.conf /etc/ipsec.d/ikev2-oe.conf
cp policies/* /etc/ipsec.d/policies/
echo "192.1.3.0/24"  >> /etc/ipsec.d/policies/clear-or-private
../../guestbin/ip.sh address add 192.1.2.66/24 dev eth1
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
# "loaded private key"
ipsec whack --listpubkeys
# "has private key"
ipsec whack --listpubkeys
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 6,' -- ipsec auto --status
echo "initdone"
