# give auto's time to load
sleep 5
# this should show phase2alg picked is aes128-sha1, not null-sha1
ipsec status |grep good |grep ESP
echo done
