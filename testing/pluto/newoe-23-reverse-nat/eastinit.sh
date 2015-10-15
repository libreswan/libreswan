/testing/guestbin/swan-prep
cp policies/* /etc/ipsec.d/policies/
echo "192.1.3.0/24"  >> /etc/ipsec.d/policies/private-or-clear
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
# disable sending deletes to test if road deletes incomplete states
ipsec whack --debugall --impair-no-send-delete
# give OE policies time to load
sleep 5
echo "initdone"
