#
# $Id: net.west.sh,v 1.6 2004/04/16 19:46:17 mcr Exp $
#

if [ -n "$UML_west_CTL" ]
then
    net_eth0="eth0=daemon,10:00:00:ab:cd:ff,unix,$UML_west_CTL,$UML_west_DATA";
elif [ -n "$UML_private_CTL" ]
then
    net_eth0="eth0=daemon,10:00:00:ab:cd:ff,unix,$UML_private_CTL,$UML_private_DATA";
else
    net_eth0="eth0=mcast,10:00:00:ab:cd:ff,239.192.0.2,40800";
fi

if [ -n "$UML_public_CTL" ]
then
    net_eth1="eth1=daemon,10:00:00:64:64:45,unix,$UML_public_CTL,$UML_public_DATA";
else
    net_eth1="eth1=mcast,10:00:00:64:64:45,239.192.1.2,31200";
fi

if [ -n "$UML_admin_CTL" ]
then
    net_eth2="eth2=daemon,10:00:00:32:64:45,unix,$UML_admin_CTL,$UML_admin_DATA";
else
    net_eth2="eth2=mcast,10:00:00:32:64:45,239.192.3.2,31210";
fi

net="$net_eth0 $net_eth1 $net_eth2"



