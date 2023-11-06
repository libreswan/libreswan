export EF_DISABLE_BANNER=1
ipsec pluto --impair helper_thread_delay:1 --config /etc/ipsec.conf
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
