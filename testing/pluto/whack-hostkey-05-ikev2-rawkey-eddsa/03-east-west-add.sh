# fix/add hostkey config
cp ipsec.conf /etc/ipsec.conf
cat OUTPUT/east.hostkey >>/etc/ipsec.conf
cat OUTPUT/west.hostkey >>/etc/ipsec.conf
cat /etc/ipsec.conf
ipsec auto --add hostkey
