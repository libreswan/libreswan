#ipsec auto --up rw
#for i in `seq 1 10`; do ip netnet exec $name$i ipsec whack --asynchronous --rundir /tmp/run$i --name user$i  --initiate; done
#sleep 20
#
# to get a root inside the namespace, run this on road:
# ip netns exec $space1 bash
echo done
