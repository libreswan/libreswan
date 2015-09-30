/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
echo "192.1.3.0/24"  >> /etc/ipsec.d/policies/clear-or-private
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
# give OE policies time to load
sleep 5
# temp workaround for outgoing packet matching packetdefault instead of private-or-clear
ipsec auto --delete packetdefault
ipsec whack --debug-all --impair-send-no-ikev2-auth
echo "initdone"
