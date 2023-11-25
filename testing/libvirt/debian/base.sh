#!/bin/sh

echo
echo
echo

# this is run from within /target

echo
echo profile
echo

cat <<EOF | tee /root/.profile
PS1='[\u@\h \w \$(echo \$?)]\\$ '
EOF

echo
echo grub
echo

sed -i -e 's/GRUB_TIMEOUT=.*/GRUB_TIMEOUT=0/' /etc/default/grub
update-grub


echo
echo fstab
echo

mkdir -p /pool /bench
cat <<EOF | tee -a /etc/fstab
@@GATEWAY@@:@@POOLDIR@@  /pool  nfs rw,tcp 0 0
@@GATEWAY@@:@@BENCHDIR@@ /bench nfs rw,tcp 0 0
EOF


echo
echo network
echo

cp /usr/lib/systemd/system/systemd-networkd-wait-online.service /etc/systemd/system
sed -i -e '/ExecStart/ s/$/ --interface eth0:routable/' /etc/systemd/system/systemd-networkd-wait-online.service
systemctl enable systemd-networkd-wait-online.service


echo
echo
echo
