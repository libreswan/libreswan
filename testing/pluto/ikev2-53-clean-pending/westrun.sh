ipsec auto --status | grep westnet-eastnet-ipv4-psk-ikev2
# wait for the IKE SA to die
../../guestbin/wait-for.sh --timeout 40 --match '#2: pending Child SA' -- ipsec auto --status
ipsec auto --status | grep westnet-eastnet-ipv4-psk-ikev2
