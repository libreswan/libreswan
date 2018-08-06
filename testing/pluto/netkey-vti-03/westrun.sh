ipsec auto --up  westnet-eastnet-vti-01
ipsec auto --up  westnet-eastnet-vti-02
# our two ranges should orute into the vti device
ip route list
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ping -n -c 4 -I 10.0.1.254 10.0.2.254
ipsec whack --trafficstatus
# show packets went via ipsec0
ifconfig ipsec0
# show how our tunnel interface looks
ip tun
echo done
