/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
# this should fail, subnet= rejected by pluto
ipsec auto --add first
# now append a second conn; still rejected by pluto
echo 'conn second' >> /etc/ipsec.conf
echo '        left=2.3.4.5' >> /etc/ipsec.conf
echo '        right=5.6.7.8' >> /etc/ipsec.conf
ipsec auto --add first
echo "initdone"
