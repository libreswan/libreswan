/testing/guestbin/swan-prep
# prepare to run many plutos
setenforce 0
#####brctl addbr rw
#####ip addr add 192.168.0.1/16 dev rw
iptables -t nat -I POSTROUTING -s 192.168.0.0/16 -j MASQUERADE -o eth0
for i in `seq 1 5`; do ./netns.sh $i; done
sleep 3
echo "initdone"
