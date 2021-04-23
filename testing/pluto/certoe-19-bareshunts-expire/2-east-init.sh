/testing/guestbin/swan-prep  --x509
certutil -D -n road -d sql:/etc/ipsec.d
certutil -D -n east -d sql:/etc/ipsec.d
# ipsec not used for this test
echo "initdone"
