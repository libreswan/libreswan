/testing/guestbin/swan-prep  --x509
ipsec certutil -D -n road
ipsec certutil -D -n east
# ipsec not used for this test
echo "initdone"
