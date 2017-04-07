#!/bin/sh

DIR=$(dirname $0)
pushd $DIR

mkdir -p dsset signed

rm -f keys/K* signed/*.signed dsset/dsset*

for zone in *arpa *libreswan.org;
do
dnssec-keygen -K keys -b 1024        -a RSASHA256 -n ZONE $zone;
dnssec-keygen -K keys -b 2048 -f KSK -a RSASHA256 -n ZONE $zone;
dnssec-signzone -S -K keys -x -f signed/${zone}.signed $zone
mv dsset-* dsset/
cat dsset/dsset-* >> dsset/dsset.all
done
popd

