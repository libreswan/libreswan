ipsec up tcp && ../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254 && ipsec down tcp || true
ipsec up udp && ../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254 && ipsec down udp || true
