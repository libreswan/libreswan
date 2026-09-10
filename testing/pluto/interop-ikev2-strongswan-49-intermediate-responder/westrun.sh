ipsec up intermediate-fragmentation-no # sanitize-retransmits
/testing/guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

ipsec whack --rekey-ike --name intermediate-fragmentation-no # sanitize-retransmits
/testing/guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

ipsec whack --rekey-ike --name intermediate-fragmentation-no # sanitize-retransmits
/testing/guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

ipsec down intermediate-fragmentation-no

ipsec up intermediate-fragmentation-yes # sanitize-retransmits
/testing/guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

ipsec whack --rekey-ike --name intermediate-fragmentation-yes # sanitize-retransmits
/testing/guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

ipsec whack --rekey-ike --name intermediate-fragmentation-yes # sanitize-retransmits
/testing/guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

ipsec down intermediate-fragmentation-yes
