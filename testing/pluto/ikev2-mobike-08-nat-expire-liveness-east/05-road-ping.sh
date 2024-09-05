# Because NIC rebuilt its NAT mapping this ping packet will go out,
# but the response (if there is one) will never make it back.
../../guestbin/ping-once.sh --down -I 100.64.0.1 192.0.2.254
ipsec trafficstatus
