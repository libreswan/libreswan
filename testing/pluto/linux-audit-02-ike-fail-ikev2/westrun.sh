# IKEv1 fail tests
# IKEv2 fail tests
ipsec whack --impair revival
ipsec up ikev2-failtest # sanitize-retransmits
ipsec delete ikev2-failtest

echo done
