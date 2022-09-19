# fix/add hostkey config
cp ipsec.conf /etc/ipsec.conf

# local CKAID for private key; remote pubkey
cat OUTPUT/west.ckaid >>/etc/ipsec.conf
cat OUTPUT/east.pub >>/etc/ipsec.conf
cat /etc/ipsec.conf

ipsec auto --add hostkey
