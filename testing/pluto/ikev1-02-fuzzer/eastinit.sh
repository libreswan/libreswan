/testing/guestbin/swan-prep --nokeys
# Start only one, so it is easier to spot a crash
ipsec pluto --config /etc/ipsec.conf 
../../guestbin/wait-until-pluto-started
ipsec auto --add rsasig
ipsec auto --add secret
echo "initdone"
