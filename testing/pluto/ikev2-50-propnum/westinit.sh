../../guestbin/swan-prep
# confirm that the network is alive
../../pluto/bin/wait-until-online 192.0.2.254 -I 192.0.1.254
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j LOGDROP
# confirm with a ping; expected to fail
! ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec setup start
../../pluto/bin/wait-until-pluto-started
echo "initdone"
