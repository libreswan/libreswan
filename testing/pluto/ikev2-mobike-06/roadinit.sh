/testing/guestbin/swan-prep
echo "192.0.2.252/30" >> /etc/ipsec.d/policies/clear
echo "192.1.3.252/30" >> /etc/ipsec.d/policies/clear
ifdown eth0
sed -i '/IPV6/d' /etc/sysconfig/network-scripts/ifcfg-eth0
sed -i '/IPADDR/d' /etc/sysconfig/network-scripts/ifcfg-eth0
sed -i '/GATEWAY/d' /etc/sysconfig/network-scripts/ifcfg-eth0
echo "IPADDR=192.1.3.209" >> /etc/sysconfig/network-scripts/ifcfg-eth0
echo "GATEWAY=192.1.3.254" >> /etc/sysconfig/network-scripts/ifcfg-eth0
ifup eth0
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-eastnet
echo "initdone"
