ipsec whack --impair suppress_retransmits
ipsec whack --impair revival
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
ipsec whack --impair trigger_revival:1
ipsec whack --impair trigger_revival:1
