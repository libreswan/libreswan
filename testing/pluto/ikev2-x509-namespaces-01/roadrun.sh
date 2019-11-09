num=99
# the --asynchronous causes all output to be invisible here, but you can always check /tmp/pluto*log on road after the tets
for i in `seq 1 $num`; do ip netns exec space$i ipsec whack --asynchronous --rundir /tmp/run$i --name user$i  --initiate; done
# to get a root inside the namespace, like space5, run this on road:
# ip netns exec space5 bash
echo done
