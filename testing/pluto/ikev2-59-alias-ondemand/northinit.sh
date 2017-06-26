/testing/guestbin/swan-prep
rm -fr /var/run/pluto/pluto.pid
/usr/local/sbin/ipsec _stackmanager start --netkey
PLUTO_CRYPTO_HELPER_DELAY=1 /usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf
/testing/pluto/bin/wait-until-pluto-started
echo "initdone"
