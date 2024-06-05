/testing/guestbin/swan-prep
# prepare to run many plutos
setenforce 0
# keep num= in roadinit.sh and roadrun.sh in sync
num=99
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=0
brctl addbr brrw
../../guestbin/ip.sh address add 192.168.0.254/24 brd + dev brrw
../../guestbin/ip.sh link set brrw up
sleep 10
iptables -t nat -I POSTROUTING -s 192.168.0.0/16 -j MASQUERADE -o eth0
for i in `seq 2 $num`; do ./netns.sh $i >/dev/null & done
# give namespaces time to start up plutos. run one in foreground for rough timing
./netns.sh 1
sleep 5
# some network tests to east from within namespace
ip netns exec space1 ping -c 2 192.1.2.23
ip netns exec space5 ping -c 2 192.1.2.23
ps auxw|grep pluto| wc -l
echo "initdone"
