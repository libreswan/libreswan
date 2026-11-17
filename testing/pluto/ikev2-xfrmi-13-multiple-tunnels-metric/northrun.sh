ipsec up north-east-gw # sanitize-retransmits
ipsec up north-east-sn # sanitize-retransmits

../../guestbin/ip.sh link show type xfrm
../../guestbin/ping-once.sh --up -I 192.1.3.33 192.1.2.23
../../guestbin/ping-once.sh --up -I 192.1.3.33 192.0.21.254
ipsec trafficstatus

ipsec down north-east-sn # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.1.3.33 192.1.2.23
ipsec trafficstatus

ipsec down north-east-gw # sanitize-retransmits
ipsec trafficstatus

echo done
