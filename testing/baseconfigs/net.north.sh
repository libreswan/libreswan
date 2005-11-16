#
# $Id: net.north.sh,v 1.3 2004/02/03 20:14:01 mcr Exp $
#

if [ -n "$UML_north_CTL" ]
then
    net_eth0="eth0=daemon,10:00:00:de:cd:49,unix,$UML_north_CTL,$UML_north_DATA";
else
    net_eth0="eth0=mcast,10:00:00:de:cd:49,239.192.0.3,40810";
fi

if [ -n "$UML_northpublic_CTL" ]
then
    net_eth1="eth1=daemon,10:00:00:96:96:49,unix,$UML_northpublic_CTL,$UML_northpublic_DATA";
else
    net_eth1="eth1=mcast,10:00:00:96:96:49,239.192.3.2,31205";
fi

net="$net_eth0 $net_eth1"



