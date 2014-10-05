export PLUTO_CRYPTO_HELPER_DELAY=1
export EF_DISABLE_BANNER=1
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf
# expecting 2*16 + 5 = 37 tunnels to come up
sleep 10
# waiting
sleep 10
# waiting
sleep 10
# waiting
sleep 10
# waiting
ipsec status | grep Total
echo done
