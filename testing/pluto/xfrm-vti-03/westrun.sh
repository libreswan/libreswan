ipsec up westnet-eastnet-vti-01 # sanitize-retransmits
ipsec up westnet-eastnet-vti-02 # sanitize-retransmits

# our two ranges should orute into the vti device
../../guestbin/ip-route.sh list
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 10.0.1.254 10.0.2.254
ipsec trafficstatus

# show packets went via ipsec0
ifconfig ipsec0

# show how our tunnel interface looks
ip tun | sort
echo done
