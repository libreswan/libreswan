# all is normal
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
ipsec auto --down westnet-eastnet-ipv4-psk-ikev2

# TSi
ipsec whack --impair number_of_TSi_selectors:0
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
ipsec auto --down westnet-eastnet-ipv4-psk-ikev2
ipsec whack --impair number_of_TSi_selectors:no

# TSr
ipsec whack --impair number_of_TSr_selectors:2
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
ipsec auto --down westnet-eastnet-ipv4-psk-ikev2
ipsec whack --impair number_of_TSr_selectors:no

echo done
