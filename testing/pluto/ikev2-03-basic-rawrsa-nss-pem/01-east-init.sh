/testing/guestbin/swan-prep

# scrub the db
modutil -dbdir /etc/ipsec.d -list
modutil -dbdir /etc/ipsec.d -rawlist
certutil -K -d /etc/ipsec.d

# Install the raw keys
head -1 *.pem
head -1 *.pub
cp *.pem *.pub /etc/ipsec.d/
libnsspem=/usr/lib64/libnsspem.so
libnsspem=$PWD/nss-pem/libnsspem.so
echo "" | modutil -dbdir /etc/ipsec.d/ -add nsspem -libfile ${libnsspem} -mechanisms RSA -string '/etc/ipsec.d/east.pub;/etc/ipsec.d/east.pem /etc/ipsec.d/west.pub;/etc/ipsec.d/west.pem'
certutil -K -d /etc/ipsec.d

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"
