/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west
# confirm max packets for IPsec SA is set
ipsec status |grep ipsec_life_packets
echo "initdone"
