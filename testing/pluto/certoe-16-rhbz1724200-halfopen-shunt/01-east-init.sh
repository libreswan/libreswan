/testing/guestbin/swan-prep --x509
cp policies/* /etc/ipsec.d/policies/
echo "192.1.3.209/32"  >> /etc/ipsec.d/policies/private
# do not start yet
echo "initdone"
