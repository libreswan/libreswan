# confirm tunnel is up
ipsec trafficstatus
# killing service ipsec
ipsec whack --impair send_no_delete
ipsec stop
# service killed
