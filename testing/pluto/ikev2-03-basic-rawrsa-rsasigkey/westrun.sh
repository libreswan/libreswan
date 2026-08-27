# see description.txt
ipsec add west-rsasigkey-east-rsasigkey
ipsec up west-rsasigkey-east-rsasigkey # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
