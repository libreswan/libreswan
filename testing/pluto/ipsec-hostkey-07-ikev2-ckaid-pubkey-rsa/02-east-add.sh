# fix/add hostkey config
cp ipsec.conf /etc/ipsec.conf

# local CKAID for private key; remote pubkey
cat OUTPUT/east.ckaid >>/etc/ipsec.conf
cat OUTPUT/west.pub >>/etc/ipsec.conf
cat /etc/ipsec.conf

ipsec auto --add hostkey
