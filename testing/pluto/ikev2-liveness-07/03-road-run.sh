# establish
ipsec auto --up road-east-x509-ipv4
# Tunnel should be up
../../guestbin/ping-once.sh --up -I 192.0.2.100 192.1.2.23
ipsec whack --trafficstatus

# Setting up block via iptables
iptables -I INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -I OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP

# wait for tunnel to die and (%trap/%hold) installed
../../guestbin/wait-for.sh --no-match '#2' -- ipsec whack --trafficstatus
ipsec whack --trafficstatus
ipsec whack --shuntstatus

# Remove block
iptables -D INPUT -s 192.1.2.23/32 -d 0/0 -j DROP
iptables -D OUTPUT -d 192.1.2.23/32 -s 0/0 -j DROP

# wait for revival
../../guestbin/wait-for.sh --match '#4' -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.2.100 192.1.2.23
ipsec whack --trafficstatus
