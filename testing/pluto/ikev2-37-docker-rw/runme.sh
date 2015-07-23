#!/bin/bash
# on the host
# ipsec _stackmanager start
# ipsec start
# ipsec status should show stack is netkey
#
#
set -x
docker stop $(docker ps -a -q)
docker rm $(docker ps -a -q)
ipsec version |grep klips && echo you need netkey && exit
dimage=swanbase
testname=ikev2-37-docker-rw
dnamer="road-$testname"
dnamee="east-$testname"
dnamen="nic-$testname"
didr=`docker run -h road --privileged --name $dnamer -v /home/build/libreswan:/home/build/libreswan -v /sys/fs/cgroup:/sys/fs/cgroup:ro -d $dimage /usr/sbin/init`
dide=`docker run -h east --privileged --name $dnamee -v /home/build/libreswan:/home/build/libreswan -v /sys/fs/cgroup:/sys/fs/cgroup:ro -d $dimage /usr/sbin/init`
didn=`docker run -h nic --privileged --name $dnamen  -v /home/build/libreswan:/home/build/libreswan -v /sys/fs/cgroup:/sys/fs/cgroup:ro -d $dimage /usr/sbin/init`
#
#
sleep 5
docker exec -ti $dnamer  /bin/bash -c 'cd /home/build/libreswan; make programs install' > /dev/null
docker exec -ti $dnamee  /bin/bash -c 'cd /home/build/libreswan; make programs install' > /dev/null

docker exec -ti $dnamee  ip address flush dev eth0
docker exec -ti $dnamer  ip address flush dev eth0
docker exec -ti $dnamen  ip address flush dev eth0

pipework br1 -i eth1 $didr 192.1.3.209/24
pipework br2 -i eth2 $dide 192.0.2.254/24
pipework br3 -i eth1 $dide 192.1.2.23/24
pipework br1 -i eth1 $didn 192.1.3.254/24
pipework br3 -i eth2 $didn 192.1.2.254/24
sleep 2
docker exec -it $dnamer ip route add default via 192.1.3.254
docker exec -it $dnamee ip route add default via 192.1.2.254
docker exec -it $dnamer ip route
docker exec -it $dnamee ip route
rm -fr OUTPUT
mkdir OUTPUT
eastc=OUTPUT/east.console.verbose.txt
roadc=OUTPUT/road.console.verbose.txt
nicc=OUTPUT/nic.console.verbose.txt
cmd="/testing/guestbin/swan-docker-run $testname nicinit.sh"
docker exec -ti $dnamen  /bin/bash -c "$cmd" > $nicc
cmd="/testing/guestbin/swan-docker-run $testname eastinit.sh"
docker exec -ti $dnamee  /bin/bash -c "$cmd" > $eastc
cmd="/testing/guestbin/swan-docker-run $testname roadinit.sh"
docker exec -ti $dnamer  /bin/bash -c "$cmd" > $roadc
cmd="/testing/guestbin/swan-docker-run $testname roadrun.sh"
docker exec -ti $dnamer  /bin/bash -c "$cmd" >> $roadc
../../utils/sanitize.sh
