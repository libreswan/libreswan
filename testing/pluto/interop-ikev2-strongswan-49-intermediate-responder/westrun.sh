ipsec up intermediate-fragmentation-yes
/testing/guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec whack --rekey-ike --name intermediate-fragmentation-yes
/testing/guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec down intermediate-fragmentation-yes

ipsec up intermediate-fragmentation-no
/testing/guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec whack --rekey-ike --name intermediate-fragmentation-no
/testing/guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec down intermediate-fragmentation-no
