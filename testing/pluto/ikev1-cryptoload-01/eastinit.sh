/testing/guestbin/swan-prep
ifconfig eth1:1 192.1.2.24 netmask 255.255.255.0
ifconfig eth1:2 192.1.2.25 netmask 255.255.255.0
ifconfig eth1:3 192.1.2.26 netmask 255.255.255.0
ifconfig eth1:4 192.1.2.27 netmask 255.255.255.0
ifconfig eth1:5 192.1.2.28 netmask 255.255.255.0
ifconfig eth1:6 192.1.2.29 netmask 255.255.255.0
ipsec _stackmanager start
#export PLUTO_CRYPTO_HELPER_DELAY=10
export EF_DISABLE_BANNER=1
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf
/testing/pluto/bin/wait-until-pluto-started
echo "initdone"
