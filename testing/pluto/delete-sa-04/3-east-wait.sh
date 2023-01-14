# waiting until we are within the last 50s of the IPsec SA lifetime
while (ipsec showstates QUICK_I2 |grep "EVENT_v1_REPLACE in 5"); ret=$?; [ $ret -ne 0 ]; do sleep 1; done
ipsec showstates QUICK_I2 |grep "EVENT_v1_REPLACE in"
