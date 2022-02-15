# kill pluto; host may send ICMP unreachble. with iptables it won't
ipsec whack --impair send-no-delete
ipsec stop
