export PLUTO_CRYPTO_HELPER_DELAY=1
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf
sleep 10
ipsec status | grep Total
sleep 10
ipsec status | grep Total
sleep 10
ipsec status | grep Total
sleep 10
ipsec status | grep Total
echo done
