#!/bin/sh

if [ ! -f ../../Makefile.inc ]; then
       echo "Please run this from testing/fedora-setup/ as cwd until this becomes a Makefile"
       exit 1
fi


for hostname in east west;
do
        sudo virsh create vm/$hostname.xml
        sudo virsh start $hostname
done

