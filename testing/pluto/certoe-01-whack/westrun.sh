ipsec whack --oppohere 192.1.2.45 --oppothere 192.1.2.23 # sanitize-retransmits # sanitize-retransmits
../../guestbin/ping-once.sh --up 192.1.2.23
# should show traffic
ipsec trafficstatus
echo done
