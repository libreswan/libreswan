../../guestbin/prep.sh

# force the kernel to use fixed IDs

sysctl -w net.ipsecif.use_fixed_reqid=1
unit=1
reqid_ipv4=$(($(sysctl -n net.ipsecif.reqid_base) + 2 * unit))
reqid_ipv6=$(($(sysctl -n net.ipsecif.reqid_base) + 2 * unit + 1))

ifconfig ipsec${unit} create
ifconfig ipsec${unit} -link2
ifconfig ipsec${unit} inet tunnel 192.1.2.23 192.1.2.45
ifconfig ipsec${unit} inet 198.18.23.23/24 198.18.45.45

ifconfig ipsec${unit}
ipsec _kernel policy
