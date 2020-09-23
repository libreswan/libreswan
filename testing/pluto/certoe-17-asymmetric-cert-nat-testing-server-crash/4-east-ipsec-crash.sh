# confirm tunnel is up
ipsec whack --trafficstatus
# killing service ipsec
ipsec whack --impair send-no-delete
ipsec stop
# service killed
