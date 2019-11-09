# ike fail tests
ipsec auto --up ikev1-failtest
ipsec auto --delete ikev1-failtest
ipsec auto --up ikev1-aggr-failtest
ipsec auto --delete ikev1-aggr-failtest
ipsec auto --up ikev2-failtest
ipsec auto --delete ikev2-failtest
echo done
