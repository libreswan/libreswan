/testing/guestbin/swan-prep

# scrub the db
modutil -create -dbdir /etc/ipsec.d -force

# Install the raw keys
head -1 *.pem
cp *.pem /etc/ipsec.d/
libnsspem=/usr/lib64/libnsspem.so
libnsspem=$PWD/nss-pem/libnsspem.so
echo "" | modutil -dbdir /etc/ipsec.d/ -add nsspem -libfile ${libnsspem} -mechanisms RSA -string ';/etc/ipsec.d/east.pem ;/etc/ipsec.d/west.pem'
certutil -K -d /etc/ipsec.d

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec whack --impair suppress-retransmits
echo "initdone"
