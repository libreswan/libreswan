/testing/guestbin/swan-prep
ipsec _stackmanager start 
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf 
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add west-east
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCqxAYQ2pvM/cZLxN61NKcAVcRe8yOKVpd3cOdXi7pO/BNLwcCzc4fIaCYwmwjAtfeMiQy4EVnXt2zNjOxBz71WxRdml/Vp4NYo1TAQng6gNqDKmBQj/QUPssv5QpKXVsSbG/N3ETCEnhWsuRNa/BKV0qA9NaknpIMQT74mBqJWolZ0I9WGOkpuVohCbxz0JFI8BYHr4XFb56xsJmQZPClgWU1cWI7e3QqKZ8vzurh6CodqytOha3D2pwVRK4bK6QTvmyC/dvl9ioyFSH3cyHz9rXYINipRyEj0BFnzrYzc/VjHGZWzFFCS3reiy6xObjCyxinALja5DfdBsNdbHmSl root@west" >> /root/.ssh/authorized_keys

echo "initdone"
