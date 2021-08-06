# IKEv1 fail tests
ipsec auto --up ikev1-failtest # sanitze-retransmits
ipsec auto --delete ikev1-failtest
ipsec auto --up ikev1-aggr-failtest  # sanitize-retransmits
ipsec auto --delete ikev1-aggr-failtest
# IKEv2 fail tests
ipsec auto --up ikev2-failtest # sanitize-retransmits
ipsec auto --delete ikev2-failtest

echo done
