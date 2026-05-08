ipsec up westnet-eastnet-ipv4-psk-ppk # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec down westnet-eastnet-ipv4-psk-ppk
ipsec delete westnet-eastnet-ipv4-psk-ppk
echo done
