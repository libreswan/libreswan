#!/bin/sh
set -e
DIR=$(dirname $0)
pushd $DIR

mkdir -p dsset signed keys

rm -f keys/K* signed/*.signed dsset/dsset* keys/testing.key

sign_zone()
{
	zone=$1
	dnssec-keygen -r /dev/urandom -K keys -b 1024        -a RSASHA256 -n ZONE $zone;
	dnssec-keygen -r /dev/urandom -K keys -b 2048 -f KSK -a RSASHA256 -n ZONE $zone;
	dnssec-signzone -r /dev/urandom -S -K keys -x -f signed/${zone}.signed $zone
}

for parent in 192.in-addr.arpa libreswan.org;
do
	sed -i '/IN DS /d' $parent
	for zone in *.${parent};
	do
		sign_zone $zone
		cat dsset-${zone}. >> $parent
	done
	sign_zone $parent;
	sed -i '/IN DS /d' $parent
done
mv dsset-* dsset/
cat dsset/dsset-* >> dsset/dsset.all
cat keys/*key > keys/testing.key
# to test
# dig +sigchase +trusted-key=/testing/baseconfigs/all/etc/bind/dsset/dsset.all  east.testing.libreswan.org
popd
