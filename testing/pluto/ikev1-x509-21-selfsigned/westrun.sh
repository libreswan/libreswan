ipsec up west-x509 # should succeed
# this one should fail, as east is only expecting selfsigned cert of west, not road
ipsec up road-x509 # should fail
echo "done"
