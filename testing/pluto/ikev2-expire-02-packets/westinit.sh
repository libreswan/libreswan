/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west
# confirm max packets for IPsec SA is set
ipsec status |grep ipsec_max_packets
echo "initdone"
