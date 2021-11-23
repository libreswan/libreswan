# IKEv1 fail tests
# IKEv2 fail tests
ipsec whack --impair revival
ipsec auto --up ikev2-failtest # sanitize-retransmits
ipsec auto --delete ikev2-failtest

echo done
