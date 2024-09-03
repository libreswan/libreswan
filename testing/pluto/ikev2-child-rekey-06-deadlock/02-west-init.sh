/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair revival
ipsec whack --impair suppress_retransmits
ipsec auto --add west
# iptables -A INPUT -s 192.1.2.23 -j LOG --log-prefix "east all"
# iptables -A INPUT -m u32 --u32 '0x6&0xFF=0x11' -j LOG --log-prefix  "udp log"
# iptables -A INPUT -m u32 --u32 '0x6 & 0xFF = 0x11 && 0x30 & 0xFFFFFFFF = 0x0:0x8' -j LOG --log-prefix  "ike"
# Drop the second IPsec rekey message, which is IKE Message ID: 4
# Message ID : 0 = IKE_INIT, 1 = IKE_AUTH, 2 = REKEY (First one let it go)
# 3 : DELETE, 4 = REKEY (DROP)
# iptables -A INPUT -m u32 --u32 '0x6 & 0xFF = 0x11 && 0x30 & 0xFFFFFFFF = 0x4' -j LOG --log-prefix  "ike"
iptables -A INPUT -m u32 --u32 '0x6 & 0xFF = 0x11 && 0x30 & 0xFFFFFFFF = 0x4' -j DROP
sleep 4 # XXX: why?
echo "initdone"
