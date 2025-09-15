ipsec up west-east-psk-ipv4
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec down west-east-psk-ipv4

ipsec up west-east-psk-ipv6
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec down west-east-psk-ipv6

echo done
