# Minimal Kickstart file
install
text
reboot
lang en_US.UTF-8
keyboard us
#network --bootproto=static --ip=76.10.157.78 --netmask=255.255.255.240 --gateway=76.10.157.65 --hostname west 
network --bootproto=dhcp --hostname base 
rootpw openswan
firewall --disable
selinux --enforcing
timezone --utc America/New_York
#firstboot --disable
bootloader --location=mbr --append="console=tty0 console=ttyS0,115200 rd_NO_PLYMOUTH"
zerombr
clearpart --all --initlabel
autopart
services --disabled=sm-client,sendmail,network,smartd,crond,atd

#Just core packages
#ensure we never accidentally get the openswan package
%packages
@core
# for now, let's not try and mix openswan rpm and /usr/local install of openswan
# later on, we will add an option to switch between "stock" and /usr/local openswan
-openswan
-sendmail
gdb
tcpdump
#racoon2
#nc6
%end

%post
echo "nameserver 193.110.157.123" >> /etc/resolv.conf
# TODO: if rhel/centos, we should install epel-release too
yum update -y 
yum install nc6 racoon2 -y
%end
