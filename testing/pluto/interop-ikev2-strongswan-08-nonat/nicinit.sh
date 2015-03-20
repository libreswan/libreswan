iptables -t nat -F
iptables -F
# Display the table, so we know it's correct.
iptables -t nat -L -n
iptables -L -n
echo "initdone"
