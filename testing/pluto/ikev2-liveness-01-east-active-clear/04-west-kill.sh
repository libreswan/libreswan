# kill pluto; host may send ICMP unreachble. with iptables it won't
ipsec whack --impair send_no_delete
ipsec stop
