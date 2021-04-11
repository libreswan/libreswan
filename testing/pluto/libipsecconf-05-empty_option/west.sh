/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
# this should have failed to --add 
ipsec auto --add first
echo 'conn second' >> /etc/ipsec.conf
echo '        left=2.3.4.5' >> /etc/ipsec.conf
echo '        right=5.6.7.8' >> /etc/ipsec.conf
# now it fails properly
ipsec auto --add first
echo "initdone"
