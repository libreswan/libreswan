# waiting until we are within the last 50s of the IPsec SA lifetime
while (ipsec status |grep STATE_QUICK_I2 |grep "EVENT_SA_REPLACE in 5"); ret=$?; [ $ret -ne 0 ]; do sleep 1; done
ipsec status |grep STATE_QUICK_I2 |grep "EVENT_SA_REPLACE in"
