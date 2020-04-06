ipsec auto --up west
ipsec status | grep STATE_
echo "sleep 0-50/600"
sleep 50
echo "sleep 50-100/600"
sleep 50
echo "sleep 100-150/600"
sleep 50
echo "sleep 150-200/600"
sleep 50
echo "sleep 200-250/600"
sleep 50
echo "sleep 250-300/600"
sleep 50
echo "sleep 300-350/600"
sleep 50
echo "sleep 350-400/600"
sleep 50
echo "sleep 400-450/600"
sleep 50
echo "sleep 450-500/600"
sleep 50
echo "sleep 500-550/600"
sleep 50
echo "sleep 550-600/600"
sleep 50
ipsec status | grep STATE_
grep vanish /tmp/pluto.log
echo done
