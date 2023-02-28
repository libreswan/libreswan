# all is normal
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
ipsec auto --down westnet-eastnet-ipv4-psk-ikev2

# TSi
ipsec whack --impair number-of-TSi-selectors:0
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
ipsec auto --down westnet-eastnet-ipv4-psk-ikev2
ipsec whack --impair number-of-TSi-selectors:no

# TSr
ipsec whack --impair number-of-TSr-selectors:2
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
ipsec auto --down westnet-eastnet-ipv4-psk-ikev2
ipsec whack --impair number-of-TSr-selectors:no

echo done
