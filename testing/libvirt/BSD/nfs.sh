#!/bin/bash
#This works for only Fedora(didn't test on other RHEL distributions)
set -e
#os = $(awk -F='/^NAME/{print $2;}' /etc/os-release)
#if [["$os" != "Fedora" ]]; then
#      echo "Please start the NFS Server and retry"
#fi
if grep -qF "192.1.2.0/24" /etc/exports;then
   echo "fstab entry already exists"
else
   echo "@@TESTINGDIR@@ 192.1.2.0/24(rw,no_root_squash)" > /etc/exports
fi
sudo systemctl start nfs-server > /dev/null
sudo exportfs -r