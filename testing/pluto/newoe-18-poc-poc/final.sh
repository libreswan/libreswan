# A tunnel should have established
grep "negotiated connection" /tmp/pluto.log
# check for proper state counting
hostname | grep east && ipsec status | grep "SAs: total"
sleep 10
ipsec auto --delete private-or-clear
sleep 5
# should show 0 states left
ipsec status | grep "SAs: total"
