/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west
# confirm max bytes for IPsec SA is set
ipsec status |grep ipsec_max_bytes
echo "initdone"
