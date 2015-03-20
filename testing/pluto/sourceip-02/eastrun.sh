: ping sunset
ping -n -c 1 -n 192.0.1.4
ipsec auto --up estnet--eastnet-sourceip

ping -n -c 4 -n 192.0.1.3

# now wait for the receiving end to expire its last phase 2
sleep 60

echo end

